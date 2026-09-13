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
	"golang.org/x/net/ipv4"
)

const iwanClientReadBatchSize = 32
const iwanClientWriteBatchSize = 64

type iwanWriteBatchWorkspace struct {
	messages []ipv4.Message
	pooled   []pooledWirePacket
	buffers  [iwanClientWriteBatchSize][1][]byte
}

var iwanWriteBatchWorkspacePool = sync.Pool{New: func() any {
	return &iwanWriteBatchWorkspace{
		messages: make([]ipv4.Message, 0, iwanClientWriteBatchSize),
		pooled:   make([]pooledWirePacket, 0, iwanClientWriteBatchSize),
	}
}}

// writeOutboundBatch is the native IPv4 egress fast path.  Framing and
// encryption still happen in Go, but the syscall boundary is amortized across
// a batch and all pooled frames remain owned until WriteBatch returns.
func (e *Endpoint) writeOutboundBatch(conn net.Conn, session *Session, mtu uint32, packetBuffers []*buf.Buffer) (bool, error) {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok || !isIPv4UDPConn(udpConn) {
		return false, nil
	}
	packetConn := ipv4.NewPacketConn(udpConn)
	workspace := iwanWriteBatchWorkspacePool.Get().(*iwanWriteBatchWorkspace)
	messages := workspace.messages[:0]
	pooled := workspace.pooled[:0]
	defer func() {
		clear(workspace.messages[:cap(workspace.messages)])
		clear(workspace.pooled[:cap(workspace.pooled)])
		for i := range workspace.buffers {
			workspace.buffers[i][0] = nil
		}
		workspace.messages = messages[:0]
		workspace.pooled = pooled[:0]
		iwanWriteBatchWorkspacePool.Put(workspace)
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
				return fmt.Errorf("iWAN batch write made no progress")
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
		messages = append(messages, ipv4.Message{Buffers: workspace.buffers[slot][:]})
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
	for _, packetBuffer := range packetBuffers {
		if packetBuffer.Len()+HeaderLen > int(mtu) {
			fragments, err := FragmentData(session.DataHeader(), packetBuffer.Bytes(), int(mtu), e.fragID.Add(1))
			if err != nil {
				return true, err
			}
			for _, fragment := range fragments {
				if err = appendMessage(fragment, nil, nil); err != nil {
					return true, err
				}
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

type pooledWirePacket struct {
	packet []byte
	pool   *wirePacket
}

// readLoopBatch uses recvmmsg when the dialer exposes a native UDP socket.
// Dialers that wrap the socket continue through readLoopSingle, preserving
// compatibility with proxy/tunnel transports.
func (e *Endpoint) readLoopBatch() bool {
	conn, ok := e.conn.(*net.UDPConn)
	if !ok {
		return false
	}
	// x/net/ipv4 uses the IPv4 packet socket operations.  Do not select it
	// solely from the concrete type: a UDPConn can also be connected to an
	// IPv6 peer, for which the portable reader is the compatible path.
	if !isIPv4UDPConn(conn) {
		return false
	}
	packetConn := ipv4.NewPacketConn(conn)
	messages := make([]ipv4.Message, iwanClientReadBatchSize)
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

func isIPv4UDPConn(conn *net.UDPConn) bool {
	if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.To4() != nil
	}
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.To4() != nil
	}
	return false
}
