//go:build with_iwan

package iwan

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
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
		s.header.Token = binary.BigEndian.Uint32(b[:])
		if s.header.Token == 0 {
			s.header.Token = 1
		}
	}
	return BuildOpen(s.user, s.password, s.mtu, s.encrypt, s.pipeID, s.pipeIndex, s.links)
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
		if _, _, err = VerifySigned(packet); err != nil {
			return nil, Header{}, err
		}
		s.header = control
		s.header.Type = PTData
		s.ready = true
		return nil, control, nil
	case PTOpenRej:
		return nil, control, fmt.Errorf("iWAN OPEN rejected")
	case PTData, PTDataEnc:
		if !s.ready {
			return nil, control, errors.New("iWAN session is not ready")
		}
		if control.SID != s.header.SID || control.Token != s.header.Token {
			return nil, control, errors.New("iWAN session identity mismatch")
		}
		_, payload, err = ParseData(packet)
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
	default:
		return nil, control, nil
	}
}

func (s *Session) Data(payload []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready {
		return nil, errors.New("iWAN session is not ready")
	}
	return BuildData(s.header, payload, s.user, s.password, s.encrypt), nil
}

func (s *Session) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready
}
