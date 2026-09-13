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
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/net/ipv4"
)

type serverRuntime struct {
	endpoint *Endpoint
	conn     *net.UDPConn
	// packetConn wraps the stable primary writer socket once. The standalone
	// dataplane keeps its batch socket wrapper alive for the worker lifetime;
	// recreating x/net/ipv4.PacketConn for every peer batch adds avoidable heap
	// churn on the server egress path.
	packetConn *ipv4.PacketConn
	// conns contains the SO_REUSEPORT reader set. conn remains the primary
	// writer socket so control/data egress keeps one stable source endpoint.
	// The reader set is intentionally optional: one socket is the portable
	// default, while Linux can opt into one recvmmsg owner per socket.
	conns []*net.UDPConn
	// systemDevice is one shared native TUN for the whole server endpoint.
	// A per-peer TUN cannot provide a stable kernel route once more than one
	// peer is online; responses are demultiplexed by the assigned destination
	// address in writeSharedDevice.
	device  transport.Device
	pool    netip.Prefix
	next    atomic.Uint32
	access  sync.RWMutex
	allocMu sync.Mutex
	peers   map[netip.AddrPort]*serverPeer
	byAddr  map[netip.Addr]*serverPeer
	// byAddrSnapshot is immutable after publication. The TUN egress path is
	// packet-rate and only needs a lock-free read; peer create/remove publish a
	// cloned table, which is rare compared with packet forwarding.
	byAddrSnapshot atomic.Pointer[serverPeerAddressTable]
	// bySIDSnapshot is the standalone iWAN SID fast path.  Established DATA
	// packets are authenticated by SID+token+remote tuple and therefore do not
	// need to take the server peer-map read lock on every packet.  Control and
	// reconnect packets continue to use the remote-key map below.
	bySIDSnapshot atomic.Pointer[serverPeerSIDTable]
	done          chan struct{}
	fragID        atomic.Uint32
}

type serverPeerAddressTable struct {
	peers map[netip.Addr]*serverPeer
}

type serverPeerSIDTable struct {
	peers map[uint16]*serverPeer
}

type serverPeer struct {
	remote    *net.UDPAddr
	remoteKey netip.AddrPort
	header    Header
	user      string
	password  string
	key       [16]byte
	encrypt   bool
	links     []uint32
	srPass    string
	device    transport.Device
	address   netip.Addr
	lastSeen  atomic.Int64
	writeMu   sync.Mutex
	fragMu    sync.Mutex
	frags     *FragReassembler
}

type sharedPeerBatch struct {
	peer    *serverPeer
	packets []*buf.Buffer
}

type sharedWriteWorkspace struct {
	valid      []*buf.Buffer
	validPeers []*serverPeer
	groups     []sharedPeerBatch
}

var sharedWriteWorkspacePool = sync.Pool{New: func() any {
	return &sharedWriteWorkspace{
		valid:      make([]*buf.Buffer, 0, 64),
		validPeers: make([]*serverPeer, 0, 64),
		groups:     make([]sharedPeerBatch, 0, 4),
	}
}}

func newServerRuntime(endpoint *Endpoint) *serverRuntime {
	runtime := &serverRuntime{endpoint: endpoint, peers: make(map[netip.AddrPort]*serverPeer), byAddr: make(map[netip.Addr]*serverPeer), done: make(chan struct{})}
	runtime.publishAddressSnapshotLocked()
	runtime.publishSIDSnapshotLocked()
	return runtime
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
	listenAddr := &net.UDPAddr{IP: listenIP, Port: int(port)}
	conns, err := listenIWANServerSockets(listenAddr, int(s.endpoint.options.ServerSocketReaders))
	if err != nil {
		return err
	}
	for _, conn := range conns {
		if err = conn.SetReadBuffer(iwanSocketBufferSize); err != nil {
			s.endpoint.logger.Debug("iWAN server receive buffer tuning unavailable: ", err)
		}
		if err = conn.SetWriteBuffer(iwanSocketBufferSize); err != nil {
			s.endpoint.logger.Debug("iWAN server send buffer tuning unavailable: ", err)
		}
	}
	s.conn = conns[0]
	s.conns = conns
	s.packetConn = ipv4.NewPacketConn(s.conn)
	if len(conns) > 1 {
		s.endpoint.logger.Info("iWAN server UDP ingress readers: ", len(conns))
	}
	pool := s.endpoint.options.PoolCIDR
	if pool == "" {
		pool = "10.255.0.0/24"
	}
	s.pool, err = netip.ParsePrefix(pool)
	if err != nil || !s.pool.Addr().Is4() {
		closeIWANServerSockets(conns)
		return fmt.Errorf("invalid iWAN pool %q", pool)
	}
	if s.pool.Bits() >= 31 {
		closeIWANServerSockets(conns)
		return errors.New("iWAN pool must contain at least two IPv4 addresses")
	}
	if s.endpoint.options.System {
		// Put the gateway address and the complete pool prefix on one native
		// TUN.  Linux then installs one connected route for every allocated
		// peer address, while the read side can route replies by destination.
		gatewayPrefix := netip.PrefixFrom(s.pool.Addr().Next(), s.pool.Bits())
		device, deviceErr := transport.NewDevice(transport.DeviceOptions{
			Context: s.endpoint.ctx,
			Logger:  s.endpoint.logger,
			System:  true,
			Name:    s.endpoint.options.Name,
			MTU:     s.endpoint.options.MTU,
			Configuration: transport.Configuration{
				MTU:     s.endpoint.options.MTU,
				Address: []netip.Prefix{gatewayPrefix},
			},
		})
		if deviceErr != nil {
			closeIWANServerSockets(conns)
			return E.Cause(deviceErr, "iWAN shared native device")
		}
		device.SetPacketWriter(s.writeSharedDevice)
		if deviceErr = device.Start(); deviceErr != nil {
			_ = device.Close()
			closeIWANServerSockets(conns)
			return E.Cause(deviceErr, "iWAN shared native device start")
		}
		s.device = device
	}
	go s.readLoop()
	return nil
}

func (s *serverRuntime) readLoop() {
	// The standalone iWAN dataplane uses one ingress owner per SO_REUSEPORT
	// socket. Keep the same structure here, but retain a single-reader default
	// for compatibility with kernels and transports without reuse-port.
	if len(s.conns) <= 1 {
		s.readLoopConn(s.conn, true)
		close(s.done)
		return
	}
	var readers sync.WaitGroup
	readers.Add(len(s.conns))
	for index, conn := range s.conns {
		go func(index int, conn *net.UDPConn) {
			defer readers.Done()
			// Only one reader owns idle-peer reaping; duplicate reapers would
			// be safe under the map lock but needlessly scan the same table.
			s.readLoopConn(conn, index == 0)
		}(index, conn)
	}
	readers.Wait()
	close(s.done)
}

func (s *serverRuntime) readLoopConn(conn *net.UDPConn, reapEnabled bool) {
	if s.readLoopBatch(conn, reapEnabled) {
		return
	}
	s.readLoopSingle(conn, reapEnabled)
}

func (s *serverRuntime) readLoopSingle(conn *net.UDPConn, reapEnabled bool) {
	var packet [64 * 1024]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, err := conn.ReadFromUDP(packet[:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if reapEnabled {
					s.reap(time.Now())
				}
				continue
			}
			return
		}
		peer, inbound := s.handle(packet[:n], remote)
		if inbound != nil {
			peer.lastSeen.Store(time.Now().UnixNano())
			peer.device.WriteInboundBuffers([]*buf.Buffer{inbound})
			inbound.Release()
		}
	}
}

func (s *serverRuntime) handle(packet []byte, remote *net.UDPAddr) (*serverPeer, *buf.Buffer) {
	return s.handleWithBacking(packet, remote, nil)
}

func (s *serverRuntime) handleWithBacking(packet []byte, remote *net.UDPAddr, backing []byte) (*serverPeer, *buf.Buffer) {
	viewBacking := backing
	key, ok := serverPeerKey(remote)
	if !ok {
		return nil, nil
	}
	// Established plain DATA is the dominant server ingress path.  Mirror the
	// standalone daemon's SID table so this path is lock-free after the
	// authenticated snapshot lookup. A remote tuple check prevents a stale or
	// colliding SID from being accepted from another source.
	if len(packet) >= HeaderLen && (packet[0] == PTData || packet[0] == PTDataEnc) {
		if h, parseErr := ParseHeader(packet); parseErr == nil {
			if peer := s.fastPeer(h.SID, key); peer != nil {
				return s.handleData(peer, h, packet, viewBacking)
			}
			// A SID collision or a control-plane snapshot published just
			// before this reader observed it must not turn a valid remote-key
			// session into a drop. The old locked map is the rare fallback;
			// established traffic remains lock-free in the normal case.
			s.access.RLock()
			peer := s.peers[key]
			s.access.RUnlock()
			return s.handleData(peer, h, packet, viewBacking)
		}
		return nil, nil
	}
	s.access.RLock()
	peer := s.peers[key]
	s.access.RUnlock()
	if len(packet) > 0 && packet[0] == PTSegRT {
		if peer == nil || len(peer.links) == 0 || peer.srPass == "" {
			return nil, nil
		}
		var err error
		packet, err = UnwrapSR(packet, peer.links, peer.srPass)
		if err != nil {
			return nil, nil
		}
		// UnwrapSR returns a transformed allocation, not a view into the
		// recvmmsg slot, so it cannot be exposed as a zero-copy TUN buffer.
		viewBacking = nil
	}
	h, err := ParseHeader(packet)
	if err != nil {
		return nil, nil
	}
	switch h.Type {
	case PTOpen:
		s.handleOpen(packet, remote, peer)
	case PTEchoReq:
		if peer != nil && h.SID == peer.header.SID && h.Token == peer.header.Token {
			_, payload, verifyErr := VerifySigned(packet)
			if verifyErr != nil {
				return nil, nil
			}
			peer.lastSeen.Store(time.Now().UnixNano())
			s.write(peer, BuildEchoResponse(h, payload))
		}
	case PTEchoResp:
		if peer != nil && h.SID == peer.header.SID && h.Token == peer.header.Token {
			if _, _, verifyErr := VerifySigned(packet); verifyErr != nil {
				return nil, nil
			}
			peer.lastSeen.Store(time.Now().UnixNano())
		}
	case PTData, PTDataEnc:
		return s.handleData(peer, h, packet, viewBacking)
	case PTIPFrag:
		if peer == nil || h.SID != peer.header.SID || h.Token != peer.header.Token {
			return nil, nil
		}
		fragment, fragmentErr := ParseFrag(packet)
		if fragmentErr != nil {
			return nil, nil
		}
		peer.fragMu.Lock()
		payload, fragmentErr := peer.frags.Add(fragment, time.Now().UnixNano())
		peer.fragMu.Unlock()
		if fragmentErr != nil || len(payload) == 0 {
			return nil, nil
		}
		return peer, newInboundPacketBuffer(payload)
	case PTClose:
		if peer != nil && h.SID == peer.header.SID && h.Token == peer.header.Token {
			if _, _, verifyErr := VerifySigned(packet); verifyErr == nil {
				s.remove(key)
			}
		}
	}
	return nil, nil
}

func (s *serverRuntime) fastPeer(sid uint16, key netip.AddrPort) *serverPeer {
	table := s.bySIDSnapshot.Load()
	if table == nil {
		return nil
	}
	peer := table.peers[sid]
	if peer == nil || peer.remoteKey != key || peer.header.SID != sid {
		return nil
	}
	return peer
}

func (s *serverRuntime) handleData(peer *serverPeer, h Header, packet, backing []byte) (*serverPeer, *buf.Buffer) {
	if peer == nil || h.SID != peer.header.SID || h.Token != peer.header.Token || len(packet) == HeaderLen {
		return nil, nil
	}
	payload := packet[HeaderLen:]
	if h.Type == PTDataEnc {
		if !peer.encrypt {
			return nil, nil
		}
		xorInPlace(peer.key, payload, payload)
	}
	if backing != nil {
		return peer, newInboundPacketView(backing, HeaderLen, len(payload))
	}
	return peer, newInboundPacketBuffer(payload)
}

func (s *serverRuntime) handleOpen(packet []byte, remote *net.UDPAddr, old *serverPeer) {
	h, fields, err := ParseOpen(packet)
	if err != nil {
		return
	}
	key, keyOK := serverPeerKey(remote)
	if !keyOK {
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
			s.remove(key)
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
	remoteKey, keyOK := serverPeerKey(remote)
	if !keyOK {
		return
	}
	key := remoteKey
	peer := &serverPeer{remote: remote, remoteKey: remoteKey, header: Header{Type: PTData, Encrypt: boolByte(fields.Encrypt), SID: h.SID, Token: h.Token}, user: fields.User, password: fields.Password, key: xorCredentialKey(fields.User, fields.Password), encrypt: fields.Encrypt, links: append([]uint32(nil), fields.Links...), srPass: s.endpoint.options.SRPassword, address: address, frags: NewFragReassembler()}
	if s.device != nil {
		// Native system mode uses one shared TUN.  The server-level writer
		// demultiplexes packets by their destination address.
		peer.device = s.device
	} else {
		device, deviceErr := transport.NewDevice(transport.DeviceOptions{Context: s.endpoint.ctx, Logger: s.endpoint.logger, System: false, Handler: s.endpoint, UDPTimeout: C.UDPTimeout, Name: s.endpoint.options.Name, MTU: uint32(fields.MTU), Configuration: transport.Configuration{MTU: uint32(fields.MTU), Address: []netip.Prefix{netip.PrefixFrom(address, 32)}}})
		if deviceErr != nil {
			s.endpoint.logger.Error("iWAN peer device unavailable: ", deviceErr)
			s.writeRaw(remote, BuildOpenReject(h, []byte("device unavailable")))
			return
		}
		peer.device = device
		device.SetPacketWriter(func(packets []*buf.Buffer) error { return s.writePeer(peer, packets) })
		if deviceErr = device.Start(); deviceErr != nil {
			s.endpoint.logger.Error("iWAN peer device start failed: ", deviceErr)
			_ = device.Close()
			s.writeRaw(remote, BuildOpenReject(h, []byte("device start failed")))
			return
		}
	}
	s.access.Lock()
	s.peers[key] = peer
	s.byAddr[address] = peer
	s.publishAddressSnapshotLocked()
	s.publishSIDSnapshotLocked()
	s.access.Unlock()
	peer.lastSeen.Store(time.Now().UnixNano())
	ack, ackErr := BuildOpenAck(h, AckFields{MTU: fields.MTU, IP: addr4(address), Gateway: addr4(s.pool.Addr().Next()), Encrypt: fields.Encrypt})
	if ackErr == nil {
		s.write(peer, ack)
	}
}

// writeSharedDevice is the native server TUN egress callback.  A packet read
// from the shared TUN is a response generated by the host network stack; its
// destination is the virtual address assigned to the client.  Route it back
// through exactly that client's authenticated iWAN session.
func (s *serverRuntime) writeSharedDevice(packets []*buf.Buffer) error {
	workspace := sharedWriteWorkspacePool.Get().(*sharedWriteWorkspace)
	valid := workspace.valid[:0]
	validPeers := workspace.validPeers[:0]
	groups := workspace.groups[:0]
	defer func() {
		clear(valid)
		clear(validPeers)
		for i := range groups {
			clear(groups[i].packets)
		}
		workspace.valid = valid[:0]
		workspace.validPeers = validPeers[:0]
		workspace.groups = workspace.groups[:0]
		sharedWriteWorkspacePool.Put(workspace)
	}()
	var commonPeer *serverPeer
	var firstErr error
	allSame := true
	for _, packet := range packets {
		address, ok := packetDestination(packet.Bytes())
		if !ok {
			packet.Release()
			if firstErr == nil {
				firstErr = errors.New("iWAN shared device emitted invalid IP packet")
			}
			continue
		}
		table := s.byAddrSnapshot.Load()
		var peer *serverPeer
		if table != nil {
			peer = table.peers[address]
		}
		if peer == nil {
			// No peer owns this destination anymore (for example after a
			// timeout). Drop it instead of sending it to an unrelated session.
			packet.Release()
			continue
		}
		if commonPeer == nil {
			commonPeer = peer
		}
		if commonPeer != peer {
			allSame = false
		}
		valid = append(valid, packet)
		validPeers = append(validPeers, peer)
	}
	if commonPeer == nil || len(valid) == 0 {
		return nil
	}
	if allSame {
		if err := s.writePeer(commonPeer, valid); err != nil && firstErr == nil {
			firstErr = err
		}
		return firstErr
	}
	// A mixed-destination batch is uncommon. Group it without returning early
	// so every accepted buffer is released even if one peer's socket fails.
	for i, packet := range valid {
		peer := validPeers[i]
		found := false
		for i := range groups {
			if groups[i].peer == peer {
				groups[i].packets = append(groups[i].packets, packet)
				found = true
				break
			}
		}
		if !found {
			groups = append(groups, sharedPeerBatch{peer: peer, packets: []*buf.Buffer{packet}})
		}
	}
	for _, group := range groups {
		if err := s.writePeer(group.peer, group.packets); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func packetDestination(packet []byte) (netip.Addr, bool) {
	if len(packet) < 1 {
		return netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 || int(packet[0]&0x0f) < 5 || len(packet) < int(packet[0]&0x0f)*4 {
			return netip.Addr{}, false
		}
		var address [4]byte
		copy(address[:], packet[16:20])
		return netip.AddrFrom4(address), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		var address [16]byte
		copy(address[:], packet[24:40])
		return netip.AddrFrom16(address), true
	default:
		return netip.Addr{}, false
	}
}

func (s *serverRuntime) writePeer(peer *serverPeer, packets []*buf.Buffer) error {
	defer buf.ReleaseMulti(packets)
	peer.writeMu.Lock()
	defer peer.writeMu.Unlock()
	if handled, err := s.writePeerBatch(peer, packets); handled {
		return err
	}
	for _, packet := range packets {
		if packet.Len()+HeaderLen > int(peer.device.PortMTU()) {
			first, firstPool, second, secondPool, fragmentErr := FragmentDataPooled(peer.header, packet.Bytes(), int(peer.device.PortMTU()), s.fragID.Add(1))
			if fragmentErr != nil {
				return fragmentErr
			}
			wire, wrapErr := s.wrapPeer(peer, first)
			if wrapErr != nil {
				releaseWirePacket(first, firstPool)
				releaseWirePacket(second, secondPool)
				return wrapErr
			}
			if _, err := s.conn.WriteToUDP(wire, peer.remote); err != nil {
				releaseWirePacket(first, firstPool)
				releaseWirePacket(second, secondPool)
				return err
			}
			releaseWirePacket(first, firstPool)
			wire, wrapErr = s.wrapPeer(peer, second)
			if wrapErr != nil {
				releaseWirePacket(second, secondPool)
				return wrapErr
			}
			if _, err := s.conn.WriteToUDP(wire, peer.remote); err != nil {
				releaseWirePacket(second, secondPool)
				return err
			}
			releaseWirePacket(second, secondPool)
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
		s.access.RLock()
		for _, peer := range s.peers {
			if peer.address == address {
				used = true
				break
			}
		}
		s.access.RUnlock()
		if !used {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func (s *serverRuntime) remove(key netip.AddrPort) {
	s.access.Lock()
	peer := s.peers[key]
	delete(s.peers, key)
	if peer != nil {
		delete(s.byAddr, peer.address)
		s.publishAddressSnapshotLocked()
		s.publishSIDSnapshotLocked()
	}
	s.access.Unlock()
	if peer != nil && peer.device != nil && s.device == nil {
		_ = peer.device.Close()
	}
}

func (s *serverRuntime) reap(now time.Time) {
	var expired []netip.AddrPort
	s.access.RLock()
	for key, peer := range s.peers {
		last := peer.lastSeen.Load()
		if last == 0 || now.Sub(time.Unix(0, last)) > 45*time.Second {
			expired = append(expired, key)
		}
	}
	s.access.RUnlock()
	for _, key := range expired {
		s.remove(key)
	}
}

func (s *serverRuntime) publishAddressSnapshotLocked() {
	peers := make(map[netip.Addr]*serverPeer, len(s.byAddr))
	for address, peer := range s.byAddr {
		peers[address] = peer
	}
	s.byAddrSnapshot.Store(&serverPeerAddressTable{peers: peers})
}

func (s *serverRuntime) publishSIDSnapshotLocked() {
	peers := make(map[uint16]*serverPeer, len(s.peers))
	for _, peer := range s.peers {
		if peer != nil {
			peers[peer.header.SID] = peer
		}
	}
	s.bySIDSnapshot.Store(&serverPeerSIDTable{peers: peers})
}

func serverPeerKey(remote *net.UDPAddr) (netip.AddrPort, bool) {
	if remote == nil || remote.Port < 0 || remote.Port > 65535 {
		return netip.AddrPort{}, false
	}
	ip := remote.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, false
	}
	if remote.Zone != "" {
		address = address.WithZone(remote.Zone)
	}
	return netip.AddrPortFrom(address, uint16(remote.Port)), true
}

func (s *serverRuntime) close() error {
	if len(s.conns) == 0 && s.conn == nil {
		return nil
	}
	var err error
	if len(s.conns) != 0 {
		closeIWANServerSockets(s.conns)
	} else {
		err = s.conn.Close()
	}
	if s.device != nil {
		_ = s.device.Close()
	}
	<-s.done
	s.access.Lock()
	peers := make([]*serverPeer, 0, len(s.peers))
	for key, peer := range s.peers {
		delete(s.peers, key)
		peers = append(peers, peer)
	}
	clear(s.byAddr)
	s.publishAddressSnapshotLocked()
	s.publishSIDSnapshotLocked()
	s.access.Unlock()
	for _, peer := range peers {
		if s.device == nil {
			_ = peer.device.Close()
		}
	}
	return err
}

func addr4(address netip.Addr) uint32 {
	b := address.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
