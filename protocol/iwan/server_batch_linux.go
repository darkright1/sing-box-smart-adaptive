//go:build with_iwan && linux

package iwan

import (
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	"golang.org/x/net/ipv4"
)

const iwanReadBatchSize = 16
const iwanWriteBatchSize = 32

// writePeerBatch amortizes server DATA egress.  The peer lock is owned by the
// caller; this helper only owns frame lifetime until the kernel accepts the
// batch, including partial-send retry.
func (s *serverRuntime) writePeerBatch(peer *serverPeer, packets []*buf.Buffer) (bool, error) {
	if s.conn == nil || peer == nil || peer.remote == nil || peer.remote.IP.To4() == nil {
		return false, nil
	}
	packetConn := ipv4.NewPacketConn(s.conn)
	messages := make([]ipv4.Message, 0, iwanWriteBatchSize)
	pooled := make([]pooledWirePacket, 0, iwanWriteBatchSize)
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
	appendMessage := func(wire []byte, releasePacket []byte, pool *wirePacket) error {
		messages = append(messages, ipv4.Message{Buffers: [][]byte{wire}, Addr: peer.remote})
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
	for _, packet := range packets {
		if packet.Len()+HeaderLen > int(peer.device.PortMTU()) {
			fragments, err := FragmentData(peer.header, packet.Bytes(), int(peer.device.PortMTU()), s.fragID.Add(1))
			if err != nil {
				return true, err
			}
			for _, fragment := range fragments {
				wire, err := s.wrapPeer(peer, fragment)
				if err != nil {
					return true, err
				}
				if err = appendMessage(wire, nil, nil); err != nil {
					return true, err
				}
			}
			continue
		}
		frame, pool := buildDataWithKeyPooled(peer.header, packet.Bytes(), peer.key, peer.encrypt)
		wire, err := s.wrapPeer(peer, frame)
		if err != nil {
			releaseWirePacket(frame, pool)
			return true, err
		}
		if err = appendMessage(wire, frame, pool); err != nil {
			return true, err
		}
	}
	if err := flush(); err != nil {
		return true, err
	}
	return true, nil
}

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
