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
)

var (
	_ adapter.Endpoint                    = (*Endpoint)(nil)
	_ adapter.FlowOutbound                = (*Endpoint)(nil)
	_ adapter.OutboundWithPreferredRoutes = (*Endpoint)(nil)
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.IWANEndpointOptions](registry, C.TypeIWAN, NewEndpoint)
}

type Endpoint struct {
	endpoint.Adapter
	ctx         context.Context
	router      adapter.Router
	dnsRouter   adapter.DNSRouter
	logger      log.ContextLogger
	options     option.IWANEndpointOptions
	dialer      N.Dialer
	device      transport.Device
	conn        net.Conn
	session     *Session
	server      *serverRuntime
	closeOnce   sync.Once
	started     atomic.Bool
	ready       atomic.Bool
	readDone    chan struct{}
	readErr     chan error
	readStarted atomic.Bool
	lastRx      atomic.Int64
	fragID      atomic.Uint32
	writeMu     sync.Mutex
	frags       *FragReassembler
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
	if e.options.Mode == "server" {
		if err := e.server.start(); err != nil {
			e.started.Store(false)
			return err
		}
		e.ready.Store(true)
		return nil
	}
	remote := M.ParseSocksaddrHostPort(e.options.Server, e.options.ServerPort)
	conn, err := e.dialer.DialContext(e.ctx, N.NetworkUDP, remote)
	if err != nil {
		e.started.Store(false)
		return err
	}
	e.conn = conn
	open, err := e.session.Open()
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
		_, control, handleErr := e.session.Handle(packet[:n])
		if handleErr != nil {
			if control.Type == PTOpenRej {
				_ = conn.Close()
				e.started.Store(false)
				return handleErr
			}
			continue
		}
		if control.Type == PTOpenAck && e.session.Ready() {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	address, _ := e.session.Address()
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
	if err = e.device.Start(); err != nil {
		_ = conn.Close()
		e.started.Store(false)
		return err
	}
	e.ready.Store(true)
	e.lastRx.Store(time.Now().UnixNano())
	e.readStarted.Store(true)
	go e.readLoop()
	go e.echoLoop()
	return nil
}

func (e *Endpoint) echoLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !e.started.Load() || !e.ready.Load() {
			return
		}
		packet, err := e.session.Echo()
		if err != nil {
			return
		}
		if last := e.lastRx.Load(); last != 0 && time.Since(time.Unix(0, last)) > 15*time.Second {
			// A missing ECHO response means the UDP session is no longer
			// usable. Closing the socket wakes readLoop and lets the normal
			// endpoint lifecycle report the failure to its owner.
			e.started.Store(false)
			e.ready.Store(false)
			select {
			case e.readErr <- errors.New("iWAN echo timeout"):
			default:
			}
			_ = e.conn.Close()
			return
		}
		e.writeControl(packet)
	}
}

func (e *Endpoint) readLoop() {
	defer close(e.readDone)
	var packet [64 * 1024]byte
	for e.started.Load() {
		n, err := e.conn.Read(packet[:])
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
			return
		}
		e.lastRx.Store(time.Now().UnixNano())
		wire, err := e.session.Unwrap(packet[:n])
		if err != nil {
			e.logger.Debug("iWAN source-routing packet rejected: ", err)
			continue
		}
		payload, control, err := e.session.Handle(wire)
		if err != nil {
			e.logger.Debug("iWAN packet rejected: ", err)
			continue
		}
		switch control.Type {
		case PTData, PTDataEnc:
			if len(payload) == 0 {
				continue
			}
			inbound := buf.NewSize(len(payload))
			_, _ = inbound.Write(payload)
			if err = e.device.WriteInboundBuffers([]*buf.Buffer{inbound}); err != nil {
				inbound.Release()
				select {
				case e.readErr <- err:
				default:
				}
				return
			}
		case PTEchoReq:
			e.writeControl(BuildEchoResponse(control, payload))
		case PTIPFrag:
			fragment, fragmentErr := ParseFrag(wire)
			if fragmentErr != nil {
				continue
			}
			if payload, fragmentErr = e.frags.Add(fragment, time.Now().UnixNano()); fragmentErr == nil && len(payload) != 0 {
				inbound := buf.NewSize(len(payload))
				_, _ = inbound.Write(payload)
				if fragmentErr = e.device.WriteInboundBuffers([]*buf.Buffer{inbound}); fragmentErr != nil {
					inbound.Release()
				}
			}
		case PTClose:
			e.ready.Store(false)
			e.started.Store(false)
			select {
			case e.readErr <- errors.New("iWAN peer closed session"):
			default:
			}
			return
		}
	}
}

func (e *Endpoint) writeControl(packet []byte) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	if e.conn != nil {
		_, _ = e.conn.Write(packet)
	}
}

func (e *Endpoint) writeOutbound(packetBuffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(packetBuffers)
	if !e.ready.Load() {
		return E.New("iWAN endpoint is not ready")
	}
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	for _, packetBuffer := range packetBuffers {
		if packetBuffer.Len()+HeaderLen > int(e.options.MTU) {
			fragments, fragmentErr := FragmentData(e.session.DataHeader(), packetBuffer.Bytes(), int(e.options.MTU), e.fragID.Add(1))
			if fragmentErr != nil {
				return fragmentErr
			}
			for _, fragment := range fragments {
				if _, err := e.conn.Write(fragment); err != nil {
					return err
				}
			}
			continue
		}
		packet, err := e.session.Data(packetBuffer.Bytes())
		if err != nil {
			return err
		}
		if _, err = e.conn.Write(packet); err != nil {
			return err
		}
	}
	return nil
}

func (e *Endpoint) Close() error {
	var err error
	e.closeOnce.Do(func() {
		e.started.Store(false)
		e.ready.Store(false)
		if e.options.Mode == "server" {
			if e.server != nil {
				err = e.server.close()
			}
			return
		}
		if e.conn != nil {
			if e.session != nil && e.session.Ready() {
				e.writeControl(BuildClose(e.session.DataHeader(), nil))
			}
			err = e.conn.Close()
		}
		if e.device != nil {
			if deviceErr := e.device.Close(); err == nil {
				err = deviceErr
			}
		}
		if e.readStarted.Load() {
			<-e.readDone
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
	if !e.ready.Load() {
		return E.New("iWAN endpoint is not ready")
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
	if !e.ready.Load() {
		return nil, E.New("iWAN endpoint is not ready")
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
	if !e.ready.Load() {
		return nil, netip.Addr{}, E.New("iWAN endpoint is not ready")
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
