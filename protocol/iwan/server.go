//go:build with_iwan

package iwan

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/sagernet/sing-box/constant"
	transport "github.com/sagernet/sing-box/transport/iwan"
	"github.com/sagernet/sing/common/buf"
)

type serverRuntime struct {
	endpoint *Endpoint
	conn     *net.UDPConn
	pool     netip.Prefix
	next     atomic.Uint32
	access   sync.Mutex
	allocMu  sync.Mutex
	peers    map[string]*serverPeer
	done     chan struct{}
	fragID   atomic.Uint32
}

type serverPeer struct {
	remote   *net.UDPAddr
	header   Header
	user     string
	password string
	key      [16]byte
	encrypt  bool
	links    []uint32
	srPass   string
	device   transport.Device
	address  netip.Addr
	lastSeen atomic.Int64
	writeMu  sync.Mutex
	frags    *FragReassembler
}

func newServerRuntime(endpoint *Endpoint) *serverRuntime {
	return &serverRuntime{endpoint: endpoint, peers: make(map[string]*serverPeer), done: make(chan struct{})}
}

func (s *serverRuntime) start() error {
	listenIP := net.IPv4zero
	if s.endpoint.options.Listen != nil {
		listenIP = net.ParseIP(s.endpoint.options.Listen.Build(netip.AddrFrom4([4]byte{})).String())
	}
	port := s.endpoint.options.ListenPort
	if port == 0 {
		port = 8000
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: listenIP, Port: int(port)})
	if err != nil {
		return err
	}
	if err = conn.SetReadBuffer(iwanSocketBufferSize); err != nil {
		s.endpoint.logger.Debug("iWAN server receive buffer tuning unavailable: ", err)
	}
	if err = conn.SetWriteBuffer(iwanSocketBufferSize); err != nil {
		s.endpoint.logger.Debug("iWAN server send buffer tuning unavailable: ", err)
	}
	s.conn = conn
	pool := s.endpoint.options.PoolCIDR
	if pool == "" {
		pool = "10.255.0.0/24"
	}
	s.pool, err = netip.ParsePrefix(pool)
	if err != nil || !s.pool.Addr().Is4() {
		_ = conn.Close()
		return fmt.Errorf("invalid iWAN pool %q", pool)
	}
	if s.pool.Bits() >= 31 {
		_ = conn.Close()
		return errors.New("iWAN pool must contain at least two IPv4 addresses")
	}
	go s.readLoop()
	return nil
}

func (s *serverRuntime) readLoop() {
	defer close(s.done)
	var packet [64 * 1024]byte
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, err := s.conn.ReadFromUDP(packet[:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.reap(time.Now())
				continue
			}
			return
		}
		s.handle(packet[:n], remote)
	}
}

func (s *serverRuntime) handle(packet []byte, remote *net.UDPAddr) {
	key := remote.String()
	s.access.Lock()
	peer := s.peers[key]
	s.access.Unlock()
	if len(packet) > 0 && packet[0] == PTSegRT {
		if peer == nil || len(peer.links) == 0 || peer.srPass == "" {
			return
		}
		var err error
		packet, err = UnwrapSR(packet, peer.links, peer.srPass)
		if err != nil {
			return
		}
	}
	h, err := ParseHeader(packet)
	if err != nil {
		return
	}
	switch h.Type {
	case PTOpen:
		s.handleOpen(packet, remote, peer)
	case PTEchoReq:
		if peer != nil && h.SID == peer.header.SID && h.Token == peer.header.Token {
			_, payload, verifyErr := VerifySigned(packet)
			if verifyErr != nil {
				return
			}
			peer.lastSeen.Store(time.Now().UnixNano())
			s.write(peer, BuildEchoResponse(h, payload))
		}
	case PTEchoResp:
		if peer != nil && h.SID == peer.header.SID && h.Token == peer.header.Token {
			if _, _, verifyErr := VerifySigned(packet); verifyErr != nil {
				return
			}
			peer.lastSeen.Store(time.Now().UnixNano())
		}
	case PTData, PTDataEnc:
		if peer == nil || h.SID != peer.header.SID || h.Token != peer.header.Token {
			return
		}
		peer.lastSeen.Store(time.Now().UnixNano())
		_, payload, err := parseDataView(packet)
		if err != nil {
			return
		}
		if h.Type == PTDataEnc {
			if !peer.encrypt {
				return
			}
			xorInPlace(peer.key, payload, payload)
		}
		inbound := buf.NewSize(len(payload))
		_, _ = inbound.Write(payload)
		if err = peer.device.WriteInboundBuffers([]*buf.Buffer{inbound}); err != nil {
			inbound.Release()
		}
	case PTIPFrag:
		if peer == nil || h.SID != peer.header.SID || h.Token != peer.header.Token {
			return
		}
		fragment, fragmentErr := ParseFrag(packet)
		if fragmentErr != nil {
			return
		}
		payload, fragmentErr := peer.frags.Add(fragment, time.Now().UnixNano())
		if fragmentErr != nil || len(payload) == 0 {
			return
		}
		inbound := buf.NewSize(len(payload))
		_, _ = inbound.Write(payload)
		if err = peer.device.WriteInboundBuffers([]*buf.Buffer{inbound}); err != nil {
			inbound.Release()
		}
	case PTClose:
		if peer != nil && h.SID == peer.header.SID && h.Token == peer.header.Token {
			if _, _, verifyErr := VerifySigned(packet); verifyErr == nil {
				s.remove(key)
			}
		}
	}
}

func (s *serverRuntime) handleOpen(packet []byte, remote *net.UDPAddr, old *serverPeer) {
	h, fields, err := ParseOpen(packet)
	if err != nil {
		return
	}
	for _, user := range s.endpoint.options.Users {
		if user.Username != fields.User || user.Password != fields.Password {
			continue
		}
		if old != nil {
			// A repeated OPEN from the same source is a reconnect, not an
			// ACK-only refresh. Replace the old SID/token and device so the
			// next DATA frame cannot be rejected against stale peer state.
			s.remove(remote.String())
		}
		s.createPeer(h, fields, remote)
		return
	}
	s.writeRaw(remote, BuildOpenReject(h, []byte("authentication failed")))
}

func (s *serverRuntime) createPeer(h Header, fields OpenFields, remote *net.UDPAddr) {
	address, ok := s.allocate()
	if !ok {
		s.writeRaw(remote, BuildOpenReject(h, []byte("address pool exhausted")))
		return
	}
	peer := &serverPeer{remote: remote, header: Header{Type: PTData, Encrypt: boolByte(fields.Encrypt), SID: h.SID, Token: h.Token}, user: fields.User, password: fields.Password, key: xorCredentialKey(fields.User, fields.Password), encrypt: fields.Encrypt, links: append([]uint32(nil), fields.Links...), srPass: s.endpoint.options.SRPassword, address: address, frags: NewFragReassembler()}
	device, err := transport.NewDevice(transport.DeviceOptions{Context: s.endpoint.ctx, Logger: s.endpoint.logger, System: s.endpoint.options.System, Handler: s.endpoint, UDPTimeout: C.UDPTimeout, Name: s.endpoint.options.Name, MTU: uint32(fields.MTU), Configuration: transport.Configuration{MTU: uint32(fields.MTU), Address: []netip.Prefix{netip.PrefixFrom(address, 32)}}})
	if err != nil {
		s.writeRaw(remote, BuildOpenReject(h, []byte("device unavailable")))
		return
	}
	peer.device = device
	device.SetPacketWriter(func(packets []*buf.Buffer) error { return s.writePeer(peer, packets) })
	if err = device.Start(); err != nil {
		_ = device.Close()
		s.writeRaw(remote, BuildOpenReject(h, []byte("device start failed")))
		return
	}
	s.access.Lock()
	s.peers[remote.String()] = peer
	s.access.Unlock()
	peer.lastSeen.Store(time.Now().UnixNano())
	ack, ackErr := BuildOpenAck(h, AckFields{MTU: fields.MTU, IP: addr4(address), Gateway: addr4(s.pool.Addr().Next()), Encrypt: fields.Encrypt})
	if ackErr == nil {
		s.write(peer, ack)
	}
}

func (s *serverRuntime) writePeer(peer *serverPeer, packets []*buf.Buffer) error {
	defer buf.ReleaseMulti(packets)
	peer.writeMu.Lock()
	defer peer.writeMu.Unlock()
	for _, packet := range packets {
		if packet.Len()+HeaderLen > int(peer.device.PortMTU()) {
			fragments, fragmentErr := FragmentData(peer.header, packet.Bytes(), int(peer.device.PortMTU()), s.fragID.Add(1))
			if fragmentErr != nil {
				return fragmentErr
			}
			for _, fragment := range fragments {
				wire, wrapErr := s.wrapPeer(peer, fragment)
				if wrapErr != nil {
					return wrapErr
				}
				if _, err := s.conn.WriteToUDP(wire, peer.remote); err != nil {
					return err
				}
			}
			continue
		}
		frame, pooled := buildDataWithKeyPooled(peer.header, packet.Bytes(), peer.key, peer.encrypt)
		var wrapErr error
		wire, wrapErr := s.wrapPeer(peer, frame)
		if wrapErr != nil {
			releaseWirePacket(frame, pooled)
			return wrapErr
		}
		_, writeErr := s.conn.WriteToUDP(wire, peer.remote)
		releaseWirePacket(frame, pooled)
		if writeErr != nil {
			return writeErr
		}
	}
	return nil
}

func (s *serverRuntime) write(peer *serverPeer, packet []byte) {
	if peer == nil {
		return
	}
	peer.writeMu.Lock()
	defer peer.writeMu.Unlock()
	_, _ = s.conn.WriteToUDP(packet, peer.remote)
}

func (s *serverRuntime) wrapPeer(peer *serverPeer, packet []byte) ([]byte, error) {
	if len(peer.links) == 0 || peer.srPass == "" {
		return packet, nil
	}
	// The reference client decrypts SEGRT-wrapped IPFRAG after reassembly;
	// wrapping each fragment here would apply the transform at the wrong
	// boundary. Keep fragments in the interoperable plain form.
	if len(packet) > 0 && packet[0] == PTIPFrag {
		return packet, nil
	}
	return WrapSR(packet, peer.links, peer.srPass, 1)
}

func (s *serverRuntime) writeRaw(remote *net.UDPAddr, packet []byte) {
	if s.conn != nil {
		_, _ = s.conn.WriteToUDP(packet, remote)
	}
}

func (s *serverRuntime) allocate() (netip.Addr, bool) {
	s.allocMu.Lock()
	defer s.allocMu.Unlock()
	base := addr4(s.pool.Addr())
	limit := uint32(1) << uint32(32-s.pool.Bits())
	// Reserve the network address, gateway (first host), and final broadcast
	// address. The remaining range is [2, limit-2] inclusive.
	usable := limit - 3
	if usable == 0 {
		return netip.Addr{}, false
	}
	for i := uint32(0); i < usable; i++ {
		idx := 2 + s.next.Add(1)%usable
		candidate := base + idx
		if candidate == 0 {
			continue
		}
		address := netip.AddrFrom4([4]byte{byte(candidate >> 24), byte(candidate >> 16), byte(candidate >> 8), byte(candidate)})
		used := false
		s.access.Lock()
		for _, peer := range s.peers {
			if peer.address == address {
				used = true
				break
			}
		}
		s.access.Unlock()
		if !used {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func (s *serverRuntime) remove(key string) {
	s.access.Lock()
	peer := s.peers[key]
	delete(s.peers, key)
	s.access.Unlock()
	if peer != nil && peer.device != nil {
		_ = peer.device.Close()
	}
}

func (s *serverRuntime) reap(now time.Time) {
	var expired []string
	s.access.Lock()
	for key, peer := range s.peers {
		last := peer.lastSeen.Load()
		if last == 0 || now.Sub(time.Unix(0, last)) > 45*time.Second {
			expired = append(expired, key)
		}
	}
	s.access.Unlock()
	for _, key := range expired {
		s.remove(key)
	}
}

func (s *serverRuntime) close() error {
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	<-s.done
	s.access.Lock()
	peers := make([]*serverPeer, 0, len(s.peers))
	for key, peer := range s.peers {
		delete(s.peers, key)
		peers = append(peers, peer)
	}
	s.access.Unlock()
	for _, peer := range peers {
		_ = peer.device.Close()
	}
	return err
}

func addr4(address netip.Addr) uint32 {
	b := address.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
