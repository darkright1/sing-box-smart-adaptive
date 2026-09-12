//go:build with_iwan && linux

package iwan

import (
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

const iwanReadBatchSize = 16

// readLoopBatch uses recvmmsg through x/net/ipv4 on Linux. The packet
// buffers live for the lifetime of the loop and are handed to handle only
// synchronously, so the next receive can safely reuse them.
func (s *serverRuntime) readLoopBatch() bool {
	defer close(s.done)
	packetConn := ipv4.NewPacketConn(s.conn)
	messages := make([]ipv4.Message, iwanReadBatchSize)
	for i := range messages {
		messages[i].Buffers = [][]byte{make([]byte, 64*1024)}
	}
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := packetConn.ReadBatch(messages, 0)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.reap(time.Now())
				continue
			}
			return true
		}
		for i := 0; i < n; i++ {
			if messages[i].N <= 0 {
				continue
			}
			remote, ok := messages[i].Addr.(*net.UDPAddr)
			if !ok || remote == nil {
				continue
			}
			s.handle(messages[i].Buffers[0][:messages[i].N], remote)
		}
	}
}
