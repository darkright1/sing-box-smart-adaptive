//go:build with_iwan

package iwan

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Session is the transport-neutral iWAN control/data state machine.  Keeping
// it independent from UDP sockets and TUN devices lets the sing-box adapter
// supply its own dialer, Router and packet ownership rules without importing
// the legacy daemon loop.
type Session struct {
	mu        sync.Mutex
	client    bool
	user      string
	password  string
	srPass    string
	mtu       uint16
	encrypt   bool
	pipeID    uint16
	pipeIndex uint16
	links     []uint32
	key       [16]byte
	header    Header
	ready     bool
	address   netip.Addr
	gateway   netip.Addr
	// wire is immutable after OPENACK and is read for every data packet.  Keep
	// the hot path lock-free; control frames still use mu because they mutate
	// session state.
	wire atomic.Pointer[sessionWireState]
}

type sessionWireState struct {
	header    Header
	key       [16]byte
	encrypted bool
}

type SessionOptions struct {
	Client     bool
	Username   string
	Password   string
	SRPassword string
	MTU        uint16
	Encrypt    bool
	PipeID     uint16
	PipeIndex  uint16
	Links      []uint32
}

func NewSession(options SessionOptions) (*Session, error) {
	if options.Username == "" || len(options.Username) > 251 {
		return nil, errors.New("invalid iWAN username")
	}
	if options.MTU < 46 || options.MTU > 1600 {
		return nil, errors.New("invalid iWAN mtu")
	}
	if options.PipeIndex > 1 || options.PipeID > 1024 || len(options.Links) > 6 {
		return nil, errors.New("invalid iWAN session options")
	}
	return &Session{
		client:    options.Client,
		user:      options.Username,
		password:  options.Password,
		srPass:    options.SRPassword,
		mtu:       options.MTU,
		encrypt:   options.Encrypt,
		pipeID:    options.PipeID,
		pipeIndex: options.PipeIndex,
		links:     append([]uint32(nil), options.Links...),
		key:       xorCredentialKey(options.Username, options.Password),
	}, nil
}

// Open returns a new client OPEN frame. Calling it twice is rejected so a
// retry loop cannot accidentally create multiple logical sessions with one
// endpoint object.
func (s *Session) Open() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.client {
		return nil, errors.New("OPEN is client-only")
	}
	if s.header.SID == 0 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		s.header.SID = binary.BigEndian.Uint16(b[:2])
		if s.header.SID == 0 {
			s.header.SID = 1
		}
		s.header.Token = binary.BigEndian.Uint32(b[:])
		if s.header.Token == 0 {
			s.header.Token = 1
		}
	}
	frame, err := BuildOpen(s.user, s.password, s.mtu, s.encrypt, s.pipeID, s.pipeIndex, s.links)
	if err != nil {
		return nil, err
	}
	// BuildOpen intentionally remains a stateless compatibility helper. The
	// session wrapper supplies its stable SID/token while preserving the exact
	// signed payload emitted by that helper.
	return Signed(Header{Type: PTOpen, Encrypt: boolByte(s.encrypt), SID: s.header.SID, Token: s.header.Token}, frame[HeaderLen+SignLen:]), nil
}

// Handle validates and consumes a control/data frame. DATA payloads are
// returned without an additional copy; the caller owns the input buffer until
// it is done with the returned slice.
func (s *Session) Handle(packet []byte) (payload []byte, control Header, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	control, err = ParseHeader(packet)
	if err != nil {
		return nil, Header{}, err
	}
	switch control.Type {
	case PTOpenAck:
		if !s.client {
			return nil, Header{}, errors.New("unexpected OPENACK")
		}
		// OPENACK must belong to the exact OPEN emitted by this session.  A
		// valid signature alone is not sufficient because a shared UDP socket
		// may receive another client's control frame.
		if control.SID != s.header.SID || control.Token != s.header.Token {
			return nil, control, errors.New("iWAN OPENACK session identity mismatch")
		}
		_, payload, err = VerifySigned(packet)
		if err != nil {
			return nil, Header{}, err
		}
		tlvs, decodeErr := DecodeTLVs(payload)
		if decodeErr != nil {
			return nil, Header{}, decodeErr
		}
		var ack AckFields
		for _, tlv := range tlvs {
			switch tlv.Type {
			case 3:
				if len(tlv.Value) == 2 {
					ack.MTU = binary.BigEndian.Uint16(tlv.Value)
				}
			case 4:
				if len(tlv.Value) == 4 {
					ack.IP = binary.BigEndian.Uint32(tlv.Value)
				}
			case 6:
				if len(tlv.Value) == 4 {
					ack.Gateway = binary.BigEndian.Uint32(tlv.Value)
				}
			case 8:
				if len(tlv.Value) == 1 {
					ack.Encrypt = tlv.Value[0] != 0
				}
			}
		}
		if ack.MTU < 46 || ack.IP == 0 {
			return nil, Header{}, errors.New("iWAN OPENACK missing address or mtu")
		}
		s.header = control
		s.header.Type = PTData
		s.encrypt = ack.Encrypt
		s.mtu = ack.MTU
		s.address = netip.AddrFrom4([4]byte{byte(ack.IP >> 24), byte(ack.IP >> 16), byte(ack.IP >> 8), byte(ack.IP)})
		s.gateway = netip.AddrFrom4([4]byte{byte(ack.Gateway >> 24), byte(ack.Gateway >> 16), byte(ack.Gateway >> 8), byte(ack.Gateway)})
		s.ready = true
		s.wire.Store(&sessionWireState{header: s.header, key: s.key, encrypted: s.encrypt})
		return nil, control, nil
	case PTOpenRej:
		if control.SID != s.header.SID || control.Token != s.header.Token {
			return nil, control, errors.New("iWAN OPEN reject session identity mismatch")
		}
		return nil, control, fmt.Errorf("iWAN OPEN rejected")
	case PTData, PTDataEnc:
		if !s.ready {
			return nil, control, errors.New("iWAN session is not ready")
		}
		if control.SID != s.header.SID || control.Token != s.header.Token {
			return nil, control, errors.New("iWAN session identity mismatch")
		}
		_, payload, err = parseDataView(packet)
		if err != nil {
			return nil, control, err
		}
		if control.Type == PTDataEnc {
			if !s.encrypt {
				return nil, control, errors.New("unexpected encrypted iWAN data")
			}
			xorInPlace(s.key, payload, payload)
		}
		return payload, control, nil
	case PTIPFrag, PTEchoReq, PTEchoResp, PTClose:
		if !s.ready {
			return nil, control, errors.New("iWAN session is not ready")
		}
		if control.SID != s.header.SID || control.Token != s.header.Token {
			return nil, control, errors.New("iWAN control session identity mismatch")
		}
		if control.Type == PTEchoReq || control.Type == PTEchoResp || control.Type == PTClose {
			_, payload, verifyErr := VerifySigned(packet)
			if verifyErr != nil {
				return nil, control, verifyErr
			}
			return payload, control, nil
		}
		return nil, control, nil
	default:
		return nil, control, nil
	}
}

// Unwrap unwraps an optional source-routing envelope and returns the inner
// packet.  The links/password are session-scoped so callers cannot
// accidentally apply another peer's SR credentials.
func (s *Session) Unwrap(packet []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(packet) == 0 || packet[0] != PTSegRT {
		return packet, nil
	}
	if len(s.links) == 0 || s.srPass == "" {
		return nil, errors.New("iWAN source-routing packet without session credentials")
	}
	return UnwrapSR(packet, s.links, s.srPass)
}

// Wrap applies the configured source-routing envelope to an inner control or
// data packet.  It is a no-op when SR is not configured.
func (s *Session) Wrap(packet []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.links) == 0 || s.srPass == "" {
		return packet, nil
	}
	return WrapSR(packet, s.links, s.srPass, 1)
}

func (s *Session) Address() (netip.Addr, netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.address, s.gateway
}

func (s *Session) Data(payload []byte) ([]byte, error) {
	state := s.wire.Load()
	if state == nil {
		return nil, errors.New("iWAN session is not ready")
	}
	return buildDataWithKey(state.header, payload, state.key, state.encrypted), nil
}

// DataPooled is the allocation-reducing variant used by the endpoint data
// path. The returned frame is valid until releaseWirePacket is called after
// the synchronous datagram write completes.
func (s *Session) DataPooled(payload []byte) ([]byte, *wirePacket, error) {
	state := s.wire.Load()
	if state == nil {
		return nil, nil, errors.New("iWAN session is not ready")
	}
	packet, pooled := buildDataWithKeyPooled(state.header, payload, state.key, state.encrypted)
	return packet, pooled, nil
}

func (s *Session) Ready() bool {
	return s.wire.Load() != nil
}

func (s *Session) DataHeader() Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.header
}

func (s *Session) Echo() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready {
		return nil, errors.New("iWAN session is not ready")
	}
	h := s.header
	h.Type = PTEchoReq
	return (Echo{Header: h, Tick: uint64(time.Now().UnixNano() / 1000)}).Marshal(), nil
}
