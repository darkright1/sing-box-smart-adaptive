//go:build with_iwan && linux

package iwan

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	transport "github.com/sagernet/sing-box/transport/iwan"
	"github.com/sagernet/sing/common/buf"
	"golang.org/x/net/ipv6"
)

// Keep the IPv6 path symmetrical with the IPv4 path. The protocol/session
// framing and ownership rules are shared; only x/net's message type differs.
type iwanWriteBatch6Workspace struct {
	messages []ipv6.Message
	pooled   []pooledWirePacket
	payloads [iwanClientWriteBatchSize][]byte
	buffers  [iwanClientWriteBatchSize][1][]byte
}

var iwanWriteBatch6WorkspacePool = sync.Pool{New: func() any {
	return &iwanWriteBatch6Workspace{
		messages: make([]ipv6.Message, 0, iwanClientWriteBatchSize),
		pooled:   make([]pooledWirePacket, 0, iwanClientWriteBatchSize),
	}
}}

func (e *Endpoint) writeOutboundBatch6(conn net.Conn, packetConn *ipv6.PacketConn, session *Session, mtu uint32, packetBuffers []*buf.Buffer) (bool, error) {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok || !isIPv6UDPConn(udpConn) {
		return false, nil
	}
	if packetConn == nil {
		packetConn = ipv6.NewPacketConn(udpConn)
	}
	workspace := iwanWriteBatch6WorkspacePool.Get().(*iwanWriteBatch6Workspace)
	messages := workspace.messages[:0]
	pooled := workspace.pooled[:0]
	defer func() {
		clear(workspace.messages[:cap(workspace.messages)])
		clear(workspace.pooled[:cap(workspace.pooled)])
		clear(workspace.payloads[:])
		for i := range workspace.buffers {
			workspace.buffers[i][0] = nil
		}
		workspace.messages = messages[:0]
		workspace.pooled = pooled[:0]
		iwanWriteBatch6WorkspacePool.Put(workspace)
	}()
	flush := func() error {
		for len(messages) > 0 {
			n, err := packetConn.WriteBatch(messages, 0)
			if n > 0 {
				messages = messages[n:]
			}
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("iWAN IPv6 batch write made no progress")
			}
		}
		return nil
	}
	releasePooled := func() {
		for _, item := range pooled {
			releaseWirePacket(item.packet, item.pool)
		}
		pooled = pooled[:0]
	}
	defer releasePooled()
	appendMessage := func(packet []byte, releasePacket []byte, pool *wirePacket) error {
		slot := len(messages)
		workspace.buffers[slot][0] = packet
		messages = append(messages, ipv6.Message{Buffers: workspace.buffers[slot][:]})
		pooled = append(pooled, pooledWirePacket{packet: releasePacket, pool: pool})
		if len(messages) == cap(messages) {
			if err := flush(); err != nil {
				return err
			}
			messages = messages[:0]
			releasePooled()
		}
		return nil
	}
	canNative := nativeIwanEnabled() && len(session.links) == 0
	if canNative {
		for i, packetBuffer := range packetBuffers {
			if packetBuffer.Len()+HeaderLen > int(mtu) {
				canNative = false
				break
			}
			workspace.payloads[i] = packetBuffer.Bytes()
		}
	}
	if canNative {
		frames, pools, used, err := session.DataPooledBatch(workspace.payloads[:len(packetBuffers)])
		if err != nil {
			return true, err
		}
		if used {
			for i, frame := range frames {
				if err = appendMessage(frame, frame, pools[i]); err != nil {
					return true, err
				}
			}
			if err = flush(); err != nil {
				return true, err
			}
			return true, nil
		}
	}
	for _, packetBuffer := range packetBuffers {
		if packetBuffer.Len()+HeaderLen > int(mtu) {
			first, firstPool, second, secondPool, err := FragmentDataPooled(session.DataHeader(), packetBuffer.Bytes(), int(mtu), e.fragID.Add(1))
			if err != nil {
				return true, err
			}
			if err = appendMessage(first, first, firstPool); err != nil {
				releaseWirePacket(second, secondPool)
				return true, err
			}
			if err = appendMessage(second, second, secondPool); err != nil {
				return true, err
			}
			continue
		}
		wire, pool, err := session.DataPooled(packetBuffer.Bytes())
		if err != nil {
			return true, err
		}
		if err = appendMessage(wire, wire, pool); err != nil {
			return true, err
		}
	}
	if err := flush(); err != nil {
		return true, err
	}
	return true, nil
}

func (e *Endpoint) readLoopBatch6() bool {
	conn, ok := e.conn.(*net.UDPConn)
	if !ok || !isIPv6UDPConn(conn) {
		return false
	}
	packetConn := e.packetConn6
	if packetConn == nil {
		packetConn = ipv6.NewPacketConn(conn)
	}
	messages := make([]ipv6.Message, iwanClientReadBatchSize)
	backings := make([][]byte, iwanClientReadBatchSize)
	for i := range messages {
		backings[i] = make([]byte, transport.PacketHeadroom+64*1024)
		messages[i].Buffers = [][]byte{backings[i][transport.PacketHeadroom:]}
	}
	inboundBatch := make([]*buf.Buffer, iwanClientReadBatchSize)
	for e.started.Load() && !e.suspended.Load() {
		n, err := packetConn.ReadBatch(messages, 0)
		if err != nil {
			wasRunning := e.started.Load() && !e.suspended.Load() && !e.closed.Load()
			e.ready.Store(false)
			if !e.suspended.Load() && !e.closed.Load() && !e.onDemand() {
				e.started.Store(false)
			}
			if wasRunning && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				select {
				case e.readErr <- err:
				default:
				}
			}
			return true
		}
		inboundBatch = inboundBatch[:0]
		batchReceived := false
		for i := 0; i < n; i++ {
			if messages[i].N <= 0 {
				continue
			}
			batchReceived = true
			inbound, ok := e.decodeIncomingPacket(messages[i].Buffers[0][:messages[i].N], backings[i])
			if inbound != nil {
				inboundBatch = append(inboundBatch, inbound)
			}
			if !ok {
				buf.ReleaseMulti(inboundBatch)
				return true
			}
		}
		if batchReceived {
			e.lastRx.Store(time.Now().UnixNano())
		}
		if len(inboundBatch) > 0 {
			err := e.device.WriteInboundBuffers(inboundBatch)
			buf.ReleaseMulti(inboundBatch)
			if err != nil {
				select {
				case e.readErr <- err:
				default:
				}
				return true
			}
		}
	}
	return true
}
