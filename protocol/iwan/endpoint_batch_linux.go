//go:build with_iwan && linux

package iwan

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/sagernet/sing/common/buf"
	"golang.org/x/net/ipv4"
)

const iwanClientReadBatchSize = 16
const iwanClientWriteBatchSize = 32

// writeOutboundBatch is the native IPv4 egress fast path.  Framing and
// encryption still happen in Go, but the syscall boundary is amortized across
// a batch and all pooled frames remain owned until WriteBatch returns.
func (e *Endpoint) writeOutboundBatch(packetBuffers []*buf.Buffer) (bool, error) {
	conn, ok := e.conn.(*net.UDPConn)
	if !ok || !isIPv4UDPConn(conn) {
		return false, nil
	}
	packetConn := ipv4.NewPacketConn(conn)
	messages := make([]ipv4.Message, 0, iwanClientWriteBatchSize)
	pooled := make([]pooledWirePacket, 0, iwanClientWriteBatchSize)
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
		messages = append(messages, ipv4.Message{Buffers: [][]byte{packet}})
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
		if packetBuffer.Len()+HeaderLen > int(e.options.MTU) {
			fragments, err := FragmentData(e.session.DataHeader(), packetBuffer.Bytes(), int(e.options.MTU), e.fragID.Add(1))
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
		wire, pool, err := e.session.DataPooled(packetBuffer.Bytes())
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
	for i := range messages {
		messages[i].Buffers = [][]byte{make([]byte, 64*1024)}
	}
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
		for i := 0; i < n; i++ {
			if messages[i].N <= 0 {
				continue
			}
			if !e.processIncomingPacket(messages[i].Buffers[0][:messages[i].N]) {
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
