//go:build with_iwan

package iwan

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	transport "github.com/sagernet/sing-box/transport/iwan"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"golang.org/x/net/ipv4"
)

var (
	_ adapter.Endpoint                    = (*Endpoint)(nil)
	_ adapter.FlowOutbound                = (*Endpoint)(nil)
	_ adapter.OutboundWithPreferredRoutes = (*Endpoint)(nil)
	_ adapter.OnDemandEndpoint            = (*Endpoint)(nil)
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.IWANEndpointOptions](registry, C.TypeIWAN, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	ctx       context.Context
	router    adapter.Router
	dnsRouter adapter.DNSRouter
	logger    log.ContextLogger
	options   option.IWANEndpointOptions
	dialer    N.Dialer
	device    transport.Device
	conn      net.Conn
	// packetConn is the immutable IPv4 batch wrapper for conn.  Keeping it
	// with the authenticated session avoids constructing an x/net wrapper for
	// every TUN batch while still replacing it atomically at reconnect time.
	packetConn  *ipv4.PacketConn
	session     *Session
	server      *serverRuntime
	closeOnce   sync.Once
	started     atomic.Bool
	ready       atomic.Bool
	readDone    chan struct{}
	readErr     chan error
	readStarted atomic.Bool
	echoStarted atomic.Bool
	echoDone    chan struct{}
	closed      atomic.Bool
	suspended   atomic.Bool
	lifecycleMu sync.Mutex
	lastRx      atomic.Int64
	fragID      atomic.Uint32
	writeMu     sync.Mutex
	fragMu      sync.Mutex
	frags       *FragReassembler
}

// isIPv4UDPConn is shared by the portable lifecycle path and the Linux batch
// implementation. A concrete UDPConn may be IPv6, in which case the batch
// IPv4 socket operations are not compatible and the caller must use the
// single-packet fallback.
func isIPv4UDPConn(conn *net.UDPConn) bool {
	if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.To4() != nil
	}
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.To4() != nil
	}
	return false
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.IWANEndpointOptions) (adapter.Endpoint, error) {
	if options.Mode == "" {
		options.Mode = "client"
	}
	if options.Mode != "client" && options.Mode != "server" {
		return nil, E.New("invalid iWAN mode: ", options.Mode)
	}
	if options.Mode == "client" {
		if options.Server == "" || options.Username == "" {
			return nil, E.New("iWAN client requires server and username")
		}
		if options.ServerPort == 0 {
			options.ServerPort = 8000
		}
	}
	if options.MTU == 0 {
		options.MTU = 1400
	}
	if options.MTU < 46 || options.MTU > 1600 {
		return nil, E.New("invalid iWAN mtu")
	}
	if !tun.WithGVisor && !options.System {
		return nil, E.New("iWAN endpoint requires the with_gvisor build tag when system is false")
	}
	var outboundDialer N.Dialer
	var session *Session
	var err error
	if options.Mode == "client" {
		outboundDialer, err = dialer.NewWithOptions(dialer.Options{
			Context:          ctx,
			Options:          options.DialerOptions,
			RemoteIsDomain:   !M.ParseAddr(options.Server).IsValid(),
			ResolverOnDetour: true,
			NewDialer:        true,
		})
		if err != nil {
			return nil, err
		}
		session, err = NewSession(SessionOptions{
			Client: true, Username: options.Username, Password: options.Password,
			SRPassword: options.SRPassword, MTU: uint16(options.MTU), Encrypt: options.Encrypt,
			PipeID: options.PipeID, PipeIndex: options.PipeIndex, Links: options.Links,
		})
		if err != nil {
			return nil, err
		}
	}
	ep := &Endpoint{
		Adapter:   endpoint.NewAdapterWithDialerOptions(C.TypeIWAN, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:       ctx,
		router:    router,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		logger:    logger,
		options:   options,
		dialer:    outboundDialer,
		session:   session,
		readDone:  make(chan struct{}),
		readErr:   make(chan error, 1),
		frags:     NewFragReassembler(),
	}
	if options.Mode == "client" {
		device, deviceErr := transport.NewDevice(transport.DeviceOptions{
			Context: ctx, Logger: logger, System: options.System, Handler: ep,
			UDPTimeout:      C.UDPTimeout,
			InterfaceFinder: service.FromContext[adapter.NetworkManager](ctx).InterfaceFinder(),
			Name:            options.Name, MTU: options.MTU,
			Configuration: transport.Configuration{MTU: options.MTU, Address: options.Address},
		})
		if deviceErr != nil {
			return nil, deviceErr
		}
		ep.device = device
		device.SetPacketWriter(ep.writeOutbound)
	} else {
		ep.server = newServerRuntime(ep)
	}
	return ep, nil
}

func (e *Endpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if e.started.Swap(true) {
		return nil
	}
	e.closed.Store(false)
	if e.options.Mode == "server" {
		if err := e.server.start(); err != nil {
			e.started.Store(false)
			return err
		}
		e.ready.Store(true)
		return nil
	}
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.startClientLocked(e.ctx, true)
}

// startClientLocked establishes a fresh authenticated session. The virtual
// device is created once and retained across on-demand suspends; only the
// network session and its reader goroutines are replaced.
func (e *Endpoint) startClientLocked(ctx context.Context, initial bool) error {
	if e.closed.Load() {
		return net.ErrClosed
	}
	if !initial {
		e.started.Store(true)
	}
	remote := M.ParseSocksaddrHostPort(e.options.Server, e.options.ServerPort)
	conn, err := e.dialer.DialContext(ctx, N.NetworkUDP, remote)
	if err != nil {
		e.started.Store(false)
		return err
	}
	e.conn = conn
	e.packetConn = nil
	if udpConn, ok := conn.(*net.UDPConn); ok && isIPv4UDPConn(udpConn) {
		e.packetConn = ipv4.NewPacketConn(udpConn)
	}
	if bufferErr := tunePacketSocket(conn); bufferErr != nil {
		e.logger.Debug("iWAN socket buffer tuning unavailable: ", bufferErr)
	}
	session, err := NewSession(SessionOptions{
		Client: true, Username: e.options.Username, Password: e.options.Password,
		SRPassword: e.options.SRPassword, MTU: uint16(e.options.MTU), Encrypt: e.options.Encrypt,
		PipeID: e.options.PipeID, PipeIndex: e.options.PipeIndex, Links: e.options.Links,
	})
	if err != nil {
		_ = conn.Close()
		e.started.Store(false)
		return err
	}
	e.session = session
	open, err := session.Open()
	if err != nil {
		_ = conn.Close()
		e.started.Store(false)
		return err
	}
	if _, err = conn.Write(open); err != nil {
		_ = conn.Close()
		e.started.Store(false)
		return err
	}
	if err = conn.SetReadDeadline(time.Now().Add(6 * time.Second)); err != nil {
		_ = conn.Close()
		e.started.Store(false)
		return err
	}
	var packet [64 * 1024]byte
	for {
		n, readErr := conn.Read(packet[:])
		if readErr != nil {
			_ = conn.Close()
			e.started.Store(false)
			return E.Cause(readErr, "iWAN OPEN")
		}
		_, control, handleErr := session.Handle(packet[:n])
		if handleErr != nil {
			if control.Type == PTOpenRej {
				_ = conn.Close()
				e.started.Store(false)
				return handleErr
			}
			continue
		}
		if control.Type == PTOpenAck && session.Ready() {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	address, _ := session.Address()
	if !address.IsValid() {
		_ = conn.Close()
		e.started.Store(false)
		return errors.New("iWAN server returned no tunnel address")
	}
	if len(e.options.Address) == 0 {
		if err = e.device.UpdateConfiguration(transport.Configuration{MTU: e.options.MTU, Address: []netip.Prefix{netip.PrefixFrom(address, 32)}}); err != nil {
			_ = conn.Close()
			e.started.Store(false)
			return err
		}
	}
	if initial {
		if err = e.device.Start(); err != nil {
			_ = conn.Close()
			e.started.Store(false)
			return err
		}
	}
	e.ready.Store(true)
	e.suspended.Store(false)
	e.lastRx.Store(time.Now().UnixNano())
	e.readDone = make(chan struct{})
	e.readStarted.Store(true)
	e.echoDone = make(chan struct{})
	e.echoStarted.Store(true)
	go e.readLoop()
	go e.echoLoop(session, e.echoDone)
	return nil
}

func (e *Endpoint) echoLoop(session *Session, done chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	defer func() {
		close(done)
		e.echoStarted.Store(false)
	}()
	for range ticker.C {
		if !e.started.Load() || !e.ready.Load() || e.suspended.Load() || e.closed.Load() {
			return
		}
		packet, err := session.Echo()
		if err != nil {
			return
		}
		if last := e.lastRx.Load(); last != 0 && time.Since(time.Unix(0, last)) > 15*time.Second {
			// A missing ECHO response means the UDP session is no longer
			// usable. Closing the socket wakes readLoop and lets the normal
			// endpoint lifecycle report the failure to its owner.
			e.lifecycleMu.Lock()
			e.ready.Store(false)
			if !e.onDemand() {
				e.started.Store(false)
			}
			conn := e.conn
			e.lifecycleMu.Unlock()
			select {
			case e.readErr <- errors.New("iWAN echo timeout"):
			default:
			}
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
		e.writeControl(packet)
	}
}

func (e *Endpoint) readLoop() {
	done := e.readDone
	defer func() {
		close(done)
		e.readStarted.Store(false)
	}()
	if e.readLoopBatch() {
		return
	}
	e.readLoopSingle()
}

func (e *Endpoint) readLoopSingle() {
	var packet [64 * 1024]byte
	conn := e.conn
	for e.started.Load() && !e.suspended.Load() {
		n, err := conn.Read(packet[:])
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
			return
		}
		if !e.processIncomingPacket(packet[:n]) {
			return
		}
	}
}

// processIncomingPacket consumes one datagram synchronously. The caller must
// not reuse the receive buffer until this function returns.
func (e *Endpoint) processIncomingPacket(packet []byte) bool {
	e.lastRx.Store(time.Now().UnixNano())
	inbound, ok := e.decodeIncomingPacket(packet, nil)
	if inbound == nil {
		return ok
	}
	err := e.device.WriteInboundBuffers([]*buf.Buffer{inbound})
	inbound.Release()
	if err != nil {
		select {
		case e.readErr <- err:
		default:
		}
		return false
	}
	return ok
}

// decodeIncomingPacket validates and unwraps one datagram.  Data packets are
// returned as owned buffers so Linux recvmmsg callers can submit a whole
// batch to the TUN device with one write operation.
func (e *Endpoint) decodeIncomingPacket(packet []byte, backing []byte) (*buf.Buffer, bool) {
	viewBacking := backing
	wire, err := e.session.Unwrap(packet)
	if err != nil {
		e.logger.Debug("iWAN source-routing packet rejected: ", err)
		return nil, true
	}
	if len(packet) > 0 && packet[0] == PTSegRT {
		viewBacking = nil
	}
	payload, control, err := e.session.Handle(wire)
	if err != nil {
		e.logger.Debug("iWAN packet rejected: ", err)
		return nil, true
	}
	switch control.Type {
	case PTData, PTDataEnc:
		if len(payload) == 0 {
			return nil, true
		}
		if viewBacking != nil {
			return newInboundPacketView(viewBacking, HeaderLen, len(payload)), true
		}
		return newInboundPacketBuffer(payload), true
	case PTEchoReq:
		e.writeControl(BuildEchoResponse(control, payload))
	case PTIPFrag:
		fragment, fragmentErr := ParseFragView(wire)
		if fragmentErr != nil {
			return nil, true
		}
		e.fragMu.Lock()
		if payload, fragmentErr = e.frags.Add(fragment, time.Now().UnixNano()); fragmentErr == nil && len(payload) != 0 {
			e.fragMu.Unlock()
			return newInboundPacketBuffer(payload), true
		}
		e.fragMu.Unlock()
	case PTClose:
		e.ready.Store(false)
		e.started.Store(false)
		select {
		case e.readErr <- errors.New("iWAN peer closed session"):
		default:
		}
		return nil, false
	}
	return nil, true
}

// newInboundPacketBuffer reserves the headroom required by native TUN
// BatchWrite up front.  Allocating only len(payload) forces systemDevice to
// allocate and copy every packet a second time before it can prepend the
// Linux TUN/VNET header.
func newInboundPacketBuffer(payload []byte) *buf.Buffer {
	packetBuffer := buf.NewSize(transport.PacketHeadroom + len(payload))
	packetBuffer.Resize(transport.PacketHeadroom, 0)
	_, _ = packetBuffer.Write(payload)
	return packetBuffer
}

// newInboundPacketView exposes an already received Linux batch slot as a
// buffer with the headroom expected by native TUN. The caller must keep the
// backing slot untouched until WriteInboundBuffers returns; all current
// batch writers are synchronous, so the next recvmmsg call can safely reuse it.
func newInboundPacketView(backing []byte, payloadOffset, payloadLen int) *buf.Buffer {
	end := transport.PacketHeadroom + payloadOffset + payloadLen
	packetBuffer := buf.As(backing[:end])
	packetBuffer.Advance(transport.PacketHeadroom + payloadOffset)
	return packetBuffer
}

func (e *Endpoint) writeControl(packet []byte) {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	if e.conn != nil {
		_, _ = e.conn.Write(packet)
	}
}

func (e *Endpoint) onDemand() bool {
	return e.options.OnDemand && e.options.Mode == "client"
}

func (e *Endpoint) OnDemand() bool { return e.onDemand() }

func (e *Endpoint) SetKeepIdleConnections(keep bool) {
	if keep || !e.onDemand() {
		return
	}
	e.suspend()
}

// suspend closes only the authenticated UDP session. The virtual device is
// retained, so resuming does not recreate host routes or the gVisor stack.
func (e *Endpoint) suspend() {
	e.lifecycleMu.Lock()
	if e.closed.Load() || e.options.Mode != "client" || e.suspended.Load() || e.conn == nil {
		e.lifecycleMu.Unlock()
		return
	}
	e.suspended.Store(true)
	e.ready.Store(false)
	conn := e.conn
	e.conn = nil
	e.packetConn = nil
	done := e.readDone
	echoDone := e.echoDone
	_ = conn.Close()
	e.lifecycleMu.Unlock()
	if done != nil {
		<-done
	}
	if echoDone != nil {
		<-echoDone
	}
}

// ensureReady resumes an on-demand client after the reference manager has
// suspended it. Waiting for the previous reader avoids overlapping sessions
// and makes the reconnect boundary explicit to the endpoint owner.
func (e *Endpoint) ensureReady(ctx context.Context) error {
	if e.options.Mode != "client" {
		if !e.ready.Load() {
			return E.New("iWAN endpoint is not ready")
		}
		return nil
	}
	if e.ready.Load() && !e.suspended.Load() {
		return nil
	}
	if !e.onDemand() {
		return E.New("iWAN endpoint is not ready")
	}
	for {
		e.lifecycleMu.Lock()
		if e.ready.Load() && !e.suspended.Load() {
			e.lifecycleMu.Unlock()
			return nil
		}
		if e.closed.Load() {
			e.lifecycleMu.Unlock()
			return net.ErrClosed
		}
		if e.readStarted.Load() || e.echoStarted.Load() {
			done := e.readDone
			echoDone := e.echoDone
			e.lifecycleMu.Unlock()
			if done != nil {
				<-done
			}
			if echoDone != nil {
				<-echoDone
			}
			continue
		}
		e.suspended.Store(false)
		err := e.startClientLocked(ctx, false)
		e.lifecycleMu.Unlock()
		return err
	}
}

func (e *Endpoint) writeOutbound(packetBuffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(packetBuffers)
	if err := e.ensureReady(e.ctx); err != nil {
		return err
	}
	e.lifecycleMu.Lock()
	if !e.ready.Load() || e.conn == nil || e.session == nil {
		e.lifecycleMu.Unlock()
		return E.New("iWAN endpoint is not ready")
	}
	conn := e.conn
	packetConn := e.packetConn
	session := e.session
	mtu := e.options.MTU
	e.lifecycleMu.Unlock()
	// Data frames are independent datagrams. The session is immutable after
	// establishment and net.Conn permits concurrent method calls, so keep the
	// lifecycle lock out of the framing and syscall hot path. Control frames
	// continue to use writeMu below.
	if handled, err := e.writeOutboundBatch(conn, packetConn, session, mtu, packetBuffers); handled {
		return err
	}
	for _, packetBuffer := range packetBuffers {
		if packetBuffer.Len()+HeaderLen > int(mtu) {
			first, firstPool, second, secondPool, fragmentErr := FragmentDataPooled(session.DataHeader(), packetBuffer.Bytes(), int(mtu), e.fragID.Add(1))
			if fragmentErr != nil {
				return fragmentErr
			}
			if _, err := conn.Write(first); err != nil {
				releaseWirePacket(first, firstPool)
				releaseWirePacket(second, secondPool)
				return err
			}
			releaseWirePacket(first, firstPool)
			if _, err := conn.Write(second); err != nil {
				releaseWirePacket(second, secondPool)
				return err
			}
			releaseWirePacket(second, secondPool)
			continue
		}
		packet, pooled, err := session.DataPooled(packetBuffer.Bytes())
		if err != nil {
			return err
		}
		_, writeErr := conn.Write(packet)
		releaseWirePacket(packet, pooled)
		if writeErr != nil {
			return writeErr
		}
	}
	return nil
}

func (e *Endpoint) Close() error {
	var err error
	e.closeOnce.Do(func() {
		e.lifecycleMu.Lock()
		e.closed.Store(true)
		e.suspended.Store(false)
		e.started.Store(false)
		e.ready.Store(false)
		if e.options.Mode == "server" {
			if e.server != nil {
				err = e.server.close()
			}
			e.lifecycleMu.Unlock()
			return
		}
		if e.conn != nil {
			if e.session != nil && e.session.Ready() {
				e.writeMu.Lock()
				_, _ = e.conn.Write(BuildClose(e.session.DataHeader(), nil))
				e.writeMu.Unlock()
			}
			err = e.conn.Close()
			e.packetConn = nil
		}
		e.lifecycleMu.Unlock()
		if e.device != nil {
			if deviceErr := e.device.Close(); err == nil {
				err = deviceErr
			}
		}
		if e.readStarted.Load() {
			<-e.readDone
		}
		if e.echoStarted.Load() && e.echoDone != nil {
			<-e.echoDone
		}
	})
	return err
}

func (e *Endpoint) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}

func (e *Endpoint) PortAddresses() (netip.Addr, netip.Addr) {
	if e.device == nil {
		return netip.Addr{}, netip.Addr{}
	}
	return e.device.PortAddresses()
}
func (e *Endpoint) PortMTU() uint32 {
	if e.device == nil {
		return e.options.MTU
	}
	return e.device.PortMTU()
}
func (e *Endpoint) AttachReturn(path tun.Return) error {
	if e.device == nil {
		return E.New("iWAN server endpoint has no shared return path")
	}
	return e.device.AttachReturn(path)
}
func (e *Endpoint) DetachReturn(path tun.Return) error {
	if e.device == nil {
		return nil
	}
	return e.device.DetachReturn(path)
}
func (e *Endpoint) WritePackets(packets [][]byte) error {
	if e.options.Mode != "client" {
		return E.New("iWAN server endpoint cannot write without a client session")
	}
	if e.device == nil {
		return E.New("iWAN server endpoint cannot write packets without a peer")
	}
	packetBuffers := make([]*buf.Buffer, 0, len(packets))
	for _, packet := range packets {
		packetBuffer := buf.NewSize(len(packet))
		_, _ = packetBuffer.Write(packet)
		packetBuffers = append(packetBuffers, packetBuffer)
	}
	return e.writeOutbound(packetBuffers)
}

func (e *Endpoint) JudgeFlow(network uint8, source, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return adapter.JudgeFlow(e.router, e.Tag(), e.Type(), network, source, destination, firstPacket)
}

func (e *Endpoint) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	var metadata adapter.InboundContext
	metadata.Inbound, metadata.InboundType = e.Tag(), e.Type()
	metadata.Network, metadata.Protocol = N.NetworkUDP, C.ProtocolDNS
	metadata.Source, metadata.Destination = source, destination
	e.router.HijackDNSPacket(log.ContextWithNewID(e.ctx), payload, writer, metadata)
}

func (e *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound, metadata.InboundType = e.Tag(), e.Type()
	metadata.Source, metadata.Destination = source, destination
	e.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound, metadata.InboundType = e.Tag(), e.Type()
	metadata.Source, metadata.Destination = source, destination
	e.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if e.options.Mode != "client" {
		return nil, E.New("iWAN server endpoint cannot dial outbound connections")
	}
	if err := e.ensureReady(ctx); err != nil {
		return nil, err
	}
	if destination.IsDomain() {
		addresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, e.device, network, destination, addresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return e.device.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	if e.options.Mode != "client" {
		return nil, netip.Addr{}, E.New("iWAN server endpoint cannot listen outbound packets")
	}
	if err := e.ensureReady(ctx); err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsDomain() {
		addresses, err := e.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		return N.ListenSerial(ctx, e.device, destination, addresses)
	}
	packetConn, err := e.device.ListenPacket(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return packetConn, destination.Addr, nil
	}
	return packetConn, netip.Addr{}, nil
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, address, err := e.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if address.IsValid() && destination != M.SocksaddrFrom(address, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(address, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (e *Endpoint) PreferredDomain(_ *adapter.InboundContext, _ string) bool { return false }
func (e *Endpoint) PreferredAddress(_ *adapter.InboundContext, address netip.Addr) bool {
	v4, v6 := e.PortAddresses()
	return address == v4 || address == v6
}
