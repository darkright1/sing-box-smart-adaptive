//go:build with_iwan && linux

package iwan

import (
	"errors"
	"io"
	"net"

	"golang.org/x/net/ipv4"
)

const iwanClientReadBatchSize = 16

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
	defer close(e.readDone)
	packetConn := ipv4.NewPacketConn(conn)
	messages := make([]ipv4.Message, iwanClientReadBatchSize)
	for i := range messages {
		messages[i].Buffers = [][]byte{make([]byte, 64*1024)}
	}
	for e.started.Load() {
		n, err := packetConn.ReadBatch(messages, 0)
		if err != nil {
			wasRunning := e.started.Load()
			e.ready.Store(false)
			e.started.Store(false)
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
