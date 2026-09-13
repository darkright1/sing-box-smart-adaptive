//go:build with_iwan && linux

package iwan

import (
	"fmt"
	"net"
	"sync"
	"time"

	transport "github.com/sagernet/sing-box/transport/iwan"
	"github.com/sagernet/sing/common/buf"
	"golang.org/x/net/ipv4"
)

// Keep server batching symmetric with the client. The arrays are fixed and
// pooled, so the larger batch trades a bounded amount of memory for fewer
// kernel crossings without introducing per-packet allocations.
const iwanReadBatchSize = 64
const iwanWriteBatchSize = 128

type iwanPeerWriteBatchWorkspace struct {
	messages []ipv4.Message
	pooled   []pooledWirePacket
	buffers  [iwanWriteBatchSize][1][]byte
}

type serverInboundWorkspace struct {
	batches map[*serverPeer][]*buf.Buffer
}

var serverInboundWorkspacePool = sync.Pool{New: func() any {
	return &serverInboundWorkspace{batches: make(map[*serverPeer][]*buf.Buffer, 2)}
}}

var iwanPeerWriteBatchWorkspacePool = sync.Pool{New: func() any {
	return &iwanPeerWriteBatchWorkspace{
		messages: make([]ipv4.Message, 0, iwanWriteBatchSize),
		pooled:   make([]pooledWirePacket, 0, iwanWriteBatchSize),
	}
}}

// writePeerBatch amortizes server DATA egress.  The peer lock is owned by the
// caller; this helper only owns frame lifetime until the kernel accepts the
// batch, including partial-send retry.
func (s *serverRuntime) writePeerBatch(peer *serverPeer, packets []*buf.Buffer) (bool, error) {
	if s.conn == nil || peer == nil || peer.remote == nil || peer.remote.IP.To4() == nil {
		return false, nil
	}
	packetConn := s.packetConn
	if packetConn == nil {
		packetConn = ipv4.NewPacketConn(s.conn)
	}
	workspace := iwanPeerWriteBatchWorkspacePool.Get().(*iwanPeerWriteBatchWorkspace)
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
		iwanPeerWriteBatchWorkspacePool.Put(workspace)
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
	appendMessage := func(wire []byte, releasePacket []byte, pool *wirePacket) error {
		slot := len(messages)
		workspace.buffers[slot][0] = wire
		messages = append(messages, ipv4.Message{Buffers: workspace.buffers[slot][:], Addr: peer.remote})
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
func (s *serverRuntime) readLoopBatch(conn *net.UDPConn, reapEnabled bool) bool {
	packetConn := ipv4.NewPacketConn(conn)
	messages := make([]ipv4.Message, iwanReadBatchSize)
	backings := make([][]byte, iwanReadBatchSize)
	for i := range messages {
		backings[i] = make([]byte, transport.PacketHeadroom+64*1024)
		messages[i].Buffers = [][]byte{backings[i][transport.PacketHeadroom:]}
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := packetConn.ReadBatch(messages, 0)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if reapEnabled {
					s.reap(time.Now())
				}
				continue
			}
			return true
		}
		workspace := serverInboundWorkspacePool.Get().(*serverInboundWorkspace)
		inboundBatches := workspace.batches
		for i := 0; i < n; i++ {
			if messages[i].N <= 0 {
				continue
			}
			remote, ok := messages[i].Addr.(*net.UDPAddr)
			if !ok || remote == nil {
				continue
			}
			peer, inbound := s.handleWithBacking(messages[i].Buffers[0][:messages[i].N], remote, backings[i])
			if inbound != nil {
				inboundBatches[peer] = append(inboundBatches[peer], inbound)
			}
		}
		now := time.Now().UnixNano()
		for peer := range inboundBatches {
			peer.lastSeen.Store(now)
		}
		for peer, inbound := range inboundBatches {
			_ = peer.device.WriteInboundBuffers(inbound)
			buf.ReleaseMulti(inbound)
		}
		clear(inboundBatches)
		serverInboundWorkspacePool.Put(workspace)
	}
}
