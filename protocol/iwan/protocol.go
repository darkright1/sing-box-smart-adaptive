//go:build with_iwan

package iwan

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"sync"
)

const (
	PTOpenRej           = 0x11
	PTOpenAck           = 0x12
	PTOpen              = 0x13
	PTData              = 0x14
	PTEchoReq           = 0x15
	PTEchoResp          = 0x16
	PTClose             = 0x17
	PTDataEnc           = 0x18
	PTIPFrag            = 0x22
	PTSegRT             = 0x28
	HeaderLen           = 8
	SignLen             = 16
	IWAN_FRAG_MAXPAY    = 2047
	IWAN_FRAG_REASM_MAX = 4096
	IWAN_FRAG_TIMEOUT   = 10
)

// Header layout is sdwan_pkthdr_t [DWARF sdwan.h:43]. Wire integers are BE.
type Header struct {
	Type, Encrypt byte
	SID           uint16
	Token         uint32
}

func (h Header) Marshal() []byte {
	b := make([]byte, 8)
	b[0] = h.Type
	b[1] = h.Encrypt
	binary.BigEndian.PutUint16(b[2:], h.SID)
	binary.BigEndian.PutUint32(b[4:], h.Token)
	return b
}
func ParseHeader(b []byte) (Header, error) {
	if len(b) < 8 {
		return Header{}, errors.New("short iwan header")
	}
	return Header{b[0], b[1], binary.BigEndian.Uint16(b[2:]), binary.BigEndian.Uint32(b[4:])}, nil
}
func Signed(h Header, payload []byte) []byte {
	b := h.Marshal()
	s := md5.Sum(append(append([]byte{}, b...), 'm', 'w'))
	return append(append(append([]byte{}, b...), s[:]...), payload...)
}
func VerifySigned(b []byte) (Header, []byte, error) {
	if len(b) < 24 {
		return Header{}, nil, errors.New("short signed packet")
	}
	h, e := ParseHeader(b)
	if e != nil {
		return h, nil, e
	}
	x := Signed(h, nil)
	if !equal(x[8:24], b[8:24]) {
		return h, nil, errors.New("invalid iwan signature")
	}
	return h, b[24:], nil
}

// BuildOpen constructs the exact client OPEN packet described in PROTOCOL.md.
// Unknown/optional TLVs are deliberately kept out of this helper so callers
// cannot accidentally emit malformed duplicate fields.
func BuildOpen(user, pass string, mtu uint16, encrypt bool, pipeID, pipeIdx uint16, links []uint32) ([]byte, error) {
	if user == "" || len(user) > 251 || mtu < 46 || mtu > 1600 {
		return nil, errors.New("invalid OPEN credentials or mtu")
	}
	ts := []TLV{{Type: 3, Value: BE16(mtu)}, {Type: 1, Value: []byte(user)}, {Type: 2, Value: PasswordCipher(user, pass)}}
	if encrypt {
		ts = append(ts, TLV{Type: 8, Value: []byte{1}})
	}
	if pipeID != 0 {
		if pipeID > 1024 || pipeIdx > 1 {
			return nil, errors.New("invalid pipe id/index")
		}
		v := pipeID | pipeIdx<<15
		ts = append(ts, TLV{Type: 10, Value: BE16(v)})
	}
	if len(links) > 6 {
		return nil, errors.New("too many SR links")
	}
	if len(links) != 0 {
		v := make([]byte, 4*len(links))
		for i, link := range links {
			binary.BigEndian.PutUint32(v[i*4:], link)
		}
		ts = append(ts, TLV{Type: 10, Value: v})
	}
	p, err := EncodeTLVs(ts)
	if err != nil {
		return nil, err
	}
	return Signed(Header{Type: PTOpen, Encrypt: boolByte(encrypt)}, p), nil
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

type OpenFields struct {
	User            string
	Password        string
	MTU             uint16
	Encrypt         bool
	PipeID, PipeIdx uint16
	Links           []uint32
}

// ParseOpen authenticates the packet envelope and decrypts the password TLV.
// It accepts reordered/unknown TLVs as the official server does.
func ParseOpen(b []byte) (Header, OpenFields, error) {
	h, p, err := VerifySigned(b)
	if err != nil {
		return Header{}, OpenFields{}, err
	}
	if h.Type != PTOpen {
		return Header{}, OpenFields{}, errors.New("not OPEN")
	}
	ts, err := DecodeTLVs(p)
	if err != nil {
		return Header{}, OpenFields{}, err
	}
	var f OpenFields
	var passCipher []byte
	for _, t := range ts {
		switch t.Type {
		case 1:
			f.User = string(t.Value)
		case 2:
			passCipher = append([]byte(nil), t.Value...)
		case 3:
			if len(t.Value) != 2 {
				return Header{}, OpenFields{}, errors.New("bad mtu TLV")
			}
			f.MTU = binary.BigEndian.Uint16(t.Value)
		case 8:
			if len(t.Value) != 1 {
				return Header{}, OpenFields{}, errors.New("bad encrypt TLV")
			}
			f.Encrypt = t.Value[0] != 0
		case 10:
			if len(t.Value) == 2 {
				v := binary.BigEndian.Uint16(t.Value)
				f.PipeID, f.PipeIdx = v&0x7fff, v>>15
			} else if len(t.Value)%4 == 0 && len(t.Value) <= 24 {
				for i := 0; i < len(t.Value); i += 4 {
					f.Links = append(f.Links, binary.BigEndian.Uint32(t.Value[i:]))
				}
			}
		}
	}
	if f.User == "" || f.MTU < 46 || f.MTU > 1600 || len(passCipher) != 16 {
		return Header{}, OpenFields{}, errors.New("OPEN missing required TLV")
	}
	plain, err := PasswordDecrypt(f.User, passCipher)
	if err != nil {
		return Header{}, OpenFields{}, err
	}
	f.Password = plain
	return h, f, nil
}

type AckFields struct {
	MTU                     uint16
	IP, Gateway, DNS0, DNS1 uint32
	Encrypt, DupPkt         bool
}

func BuildOpenAck(h Header, f AckFields) ([]byte, error) {
	if f.MTU < 46 || f.MTU > 1600 {
		return nil, errors.New("invalid ack mtu")
	}
	ts := []TLV{{3, BE16(f.MTU)}, {4, BE32(f.IP)}, {5, append(BE32(f.DNS0), BE32(f.DNS1)...)}, {6, BE32(f.Gateway)}, {8, []byte{boolByte(f.Encrypt)}}, {9, []byte{boolByte(f.DupPkt)}}}
	p, err := EncodeTLVs(ts)
	if err != nil {
		return nil, err
	}
	h.Type, h.Encrypt = PTOpenAck, boolByte(f.Encrypt)
	return Signed(h, p), nil
}

func BuildOpenReject(h Header, reason []byte) []byte { h.Type = PTOpenRej; return Signed(h, reason) }

func BuildEchoResponse(h Header, payload []byte) []byte {
	h.Type = PTEchoResp
	if len(payload) > 24 {
		payload = payload[:24]
	}
	return Signed(h, payload)
}

func BuildClose(h Header, reason []byte) []byte { h.Type = PTClose; return Signed(h, reason) }

func BuildData(h Header, payload []byte, user, pass string, encrypted bool) []byte {
	return buildDataWithKey(h, payload, xorCredentialKey(user, pass), encrypted)
}

func buildDataWithKey(h Header, payload []byte, key [16]byte, encrypted bool) []byte {
	h.Type = PTData
	h.Encrypt = boolByte(encrypted)
	if encrypted {
		h.Type = PTDataEnc
	}
	// DATA is the hottest wire format in both directions.  Build the header
	// and payload in one exact-sized allocation; the old Marshal+append path
	// could allocate twice, and encrypted DATA allocated a third copy for XOR.
	out := make([]byte, HeaderLen+len(payload))
	out[0] = h.Type
	out[1] = h.Encrypt
	binary.BigEndian.PutUint16(out[2:], h.SID)
	binary.BigEndian.PutUint32(out[4:], h.Token)
	if encrypted {
		xorInPlace(key, out[HeaderLen:], payload)
	} else {
		copy(out[HeaderLen:], payload)
	}
	return out
}

// buildDataWithKeyPooled is the internal hot-path variant used by the TUN
// data plane. The caller owns the returned buffer until releaseWirePacket;
// the public BuildData helper above intentionally keeps ordinary allocation
// semantics for callers that do not participate in the pool lifecycle.
func buildDataWithKeyPooled(h Header, payload []byte, key [16]byte, encrypted bool) ([]byte, bool) {
	h.Type = PTData
	h.Encrypt = boolByte(encrypted)
	if encrypted {
		h.Type = PTDataEnc
	}
	out, pooled := acquireWirePacket(HeaderLen + len(payload))
	out[0] = h.Type
	out[1] = h.Encrypt
	binary.BigEndian.PutUint16(out[2:], h.SID)
	binary.BigEndian.PutUint32(out[4:], h.Token)
	if encrypted {
		xorInPlace(key, out[HeaderLen:], payload)
	} else {
		copy(out[HeaderLen:], payload)
	}
	return out, pooled
}

// parseDataView validates a DATA envelope without copying its payload. The
// receive buffer is owned by the UDP batch reader and must not escape the
// caller; queueing code copies it exactly once when ownership is transferred.
func parseDataView(b []byte) (Header, []byte, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return Header{}, nil, err
	}
	if h.Type != PTData && h.Type != PTDataEnc {
		return Header{}, nil, errors.New("not DATA")
	}
	if len(b) == HeaderLen {
		return h, nil, errors.New("empty DATA")
	}
	return h, b[HeaderLen:], nil
}

func ParseData(b []byte) (Header, []byte, error) {
	h, p, err := parseDataView(b)
	if err != nil {
		return h, nil, err
	}
	return h, append([]byte(nil), p...), nil
}

// FragmentData emits the two-piece IPFRAG form accepted by the reference
// client. It intentionally refuses more than two pieces.
func FragmentData(h Header, payload []byte, mtu int, id uint32) ([][]byte, error) {
	if mtu <= HeaderLen+16 || len(payload) <= mtu-HeaderLen {
		return nil, errors.New("fragmentation not needed or mtu too small")
	}
	max := mtu - 16
	if max > IWAN_FRAG_MAXPAY {
		max = IWAN_FRAG_MAXPAY
	}
	if len(payload)-max > IWAN_FRAG_MAXPAY || len(payload) > IWAN_FRAG_REASM_MAX {
		return nil, errors.New("payload exceeds two-piece reassembly limit")
	}
	a := Frag{Header: Header{Type: PTIPFrag, Encrypt: h.Encrypt, SID: h.SID, Token: h.Token}, ID: id, Offset: 0, Payload: append([]byte(nil), payload[:max]...), Length: uint16(max)}
	b := Frag{Header: a.Header, ID: id, EOP: true, Offset: uint16(max), Payload: append([]byte(nil), payload[max:]...), Length: uint16(len(payload) - max)}
	x, err := a.Marshal()
	if err != nil {
		return nil, err
	}
	y, err := b.Marshal()
	if err != nil {
		return nil, err
	}
	return [][]byte{x, y}, nil
}

type FragReassembler struct {
	mu      sync.Mutex
	pending map[uint32]FragPiece
}
type FragPiece struct {
	Payload []byte
	At      int64
}

func NewFragReassembler() *FragReassembler {
	return &FragReassembler{pending: make(map[uint32]FragPiece)}
}

// Add returns a completed payload, or nil while waiting for the other piece.
func (r *FragReassembler) Add(f Frag, now int64) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f.Offset > IWAN_FRAG_REASM_MAX || int(f.Offset)+len(f.Payload) > IWAN_FRAG_REASM_MAX {
		return nil, errors.New("fragment exceeds reassembly buffer")
	}
	for id, p := range r.pending {
		if now-p.At > IWAN_FRAG_TIMEOUT*1e9 {
			delete(r.pending, id)
		}
	}
	if f.EOP {
		p, ok := r.pending[f.ID]
		if !ok {
			return nil, nil
		}
		if p.Payload == nil || len(p.Payload) != int(f.Offset) {
			delete(r.pending, f.ID)
			return nil, errors.New("fragment gap")
		}
		out := append(append([]byte(nil), p.Payload...), f.Payload...)
		delete(r.pending, f.ID)
		return out, nil
	}
	if f.Offset != 0 {
		return nil, errors.New("unsupported nonzero first fragment")
	}
	r.pending[f.ID] = FragPiece{append([]byte(nil), f.Payload...), now}
	return nil, nil
}

// WrapSR applies the SR AES-ECB transform to DATA payload bytes, preserving
// the inner header as specified by the reference implementation.
func WrapSR(inner []byte, links []uint32, password string, algorithm byte) ([]byte, error) {
	if len(inner) < HeaderLen || algorithm != 1 {
		return nil, errors.New("only SR AES-128 is supported")
	}
	pad := (16 - (len(inner)-HeaderLen)%16) % 16
	plain := append([]byte(nil), inner[HeaderLen:]...)
	plain = append(plain, bytes.Repeat([]byte{0}, pad)...)
	enc := AES128ECB(SRAESKey(links, password), plain, true)
	if enc == nil {
		return nil, errors.New("SR ECB failure")
	}
	encInner := append(append([]byte(nil), inner[:HeaderLen]...), enc...)
	return (SRHeader{Algorithm: algorithm, PadLen: byte(pad), Links: append([]uint32(nil), links...), Inner: encInner}).Marshal()
}

func UnwrapSR(b []byte, links []uint32, password string) ([]byte, error) {
	s, err := ParseSRHeader(b)
	if err != nil {
		return nil, err
	}
	if s.Algorithm != 1 || len(s.Inner) < HeaderLen || int(s.PadLen) > len(s.Inner)-HeaderLen {
		return nil, errors.New("invalid SR payload")
	}
	inner := append([]byte(nil), s.Inner...)
	dec := AES128ECB(SRAESKey(links, password), inner[HeaderLen:], false)
	if dec == nil {
		return nil, errors.New("SR ECB failure")
	}
	inner = append(inner[:HeaderLen], dec...)
	inner = inner[:len(inner)-int(s.PadLen)]
	return inner, nil
}

// checksum is used by tests to make accidental vector changes obvious.
func protocolChecksum(b []byte) uint32 { return crc32.ChecksumIEEE(b) }
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := range a {
		x |= a[i] ^ b[i]
	}
	return x == 0
}

type TLV struct {
	Type  byte
	Value []byte
}

func EncodeTLVs(ts []TLV) ([]byte, error) {
	var out []byte
	for _, t := range ts {
		if len(t.Value) > 253 {
			return nil, errors.New("TLV too large")
		}
		out = append(out, t.Type, byte(len(t.Value)+2))
		out = append(out, t.Value...)
	}
	return out, nil
}
func DecodeTLVs(b []byte) ([]TLV, error) {
	var out []TLV
	for len(b) > 0 {
		if len(b) < 2 || b[1] < 2 || int(b[1]) > len(b) {
			return nil, errors.New("invalid TLV")
		}
		n := int(b[1])
		out = append(out, TLV{b[0], append([]byte{}, b[2:n]...)})
		b = b[n:]
	}
	return out, nil
}
func BE16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func BE32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

func PasswordCipher(user, pass string) []byte {
	k := md5.Sum(append([]byte("mw"), []byte(user)...))
	in := make([]byte, 16)
	copy(in, pass)
	out := make([]byte, 16)
	c, _ := aes.NewCipher(k[:])
	c.Encrypt(out, in)
	return out
}
func PasswordDecrypt(user string, ciphertext []byte) (string, error) {
	if len(ciphertext) != 16 {
		return "", errors.New("password ciphertext must be 16 bytes")
	}
	k := md5.Sum(append([]byte("mw"), []byte(user)...))
	out := make([]byte, 16)
	c, _ := aes.NewCipher(k[:])
	c.Decrypt(out, ciphertext)
	n := len(out)
	for n > 0 && out[n-1] == 0 {
		n--
	}
	return string(out[:n]), nil
}
func XORData(user, pass string, b []byte) []byte {
	o := make([]byte, len(b))
	xorInPlace(xorCredentialKey(user, pass), o, b)
	return o
}

func xorCredentialKey(user, pass string) [16]byte {
	return md5.Sum([]byte(user + pass))
}

// xorInPlace applies the official 8-byte repeating XOR key. Only the first 8
// bytes of the MD5 credential digest are part of the wire format (key[i%8]).
// The word-wise loop is byte-for-byte identical to the old per-byte version
// (little-endian loads XOR the same key bytes in the same order) but runs at
// memcpy speed instead of ~300 MB/s per core.
func xorInPlace(key [16]byte, dst, src []byte) {
	k0 := binary.LittleEndian.Uint64(key[:8])
	for len(src) >= 8 {
		binary.LittleEndian.PutUint64(dst, binary.LittleEndian.Uint64(src)^k0)
		dst = dst[8:]
		src = src[8:]
	}
	for i, v := range src {
		dst[i] = v ^ key[i]
	}
}

// IPFRAG flags are the packed wire bitfield from sdwan_ethpkt_t [DWARF].
type Frag struct {
	Header         Header
	ID             uint32
	EOP            bool
	Offset, Length uint16
	Payload        []byte
}

func (f Frag) Marshal() ([]byte, error) {
	if int(f.Length) != len(f.Payload) || f.Length > 2047 || f.Offset > 8191 {
		return nil, errors.New("invalid fragment")
	}
	v := uint32(f.Offset)<<2 | uint32(f.Length)<<15
	if f.EOP {
		v |= 1
	}
	b := append(f.Header.Marshal(), make([]byte, 8)...)
	// Unlike TLV integers, sdwan_ethpkt is copied from the packed C struct;
	// the reference client reads these fields directly on little-endian Linux.
	binary.LittleEndian.PutUint32(b[8:], f.ID)
	binary.LittleEndian.PutUint32(b[12:], v)
	return append(b, f.Payload...), nil
}
func ParseFrag(b []byte) (Frag, error) {
	if len(b) < 16 {
		return Frag{}, errors.New("short fragment")
	}
	h, e := ParseHeader(b)
	if e != nil {
		return Frag{}, e
	}
	if h.Type != PTIPFrag {
		return Frag{}, errors.New("not IPFRAG")
	}
	v := binary.LittleEndian.Uint32(b[12:])
	l := uint16(v >> 15 & 2047)
	if len(b) != 16+int(l) {
		return Frag{}, fmt.Errorf("fragment length mismatch")
	}
	return Frag{h, binary.LittleEndian.Uint32(b[8:]), v&1 != 0, uint16(v >> 2 & 8191), l, append([]byte{}, b[16:]...)}, nil
}

type Echo struct {
	Header        Header
	Tick          uint64
	Cur, Min, Max uint32
	Tail          []byte
}

// SRHeader is sdwan_srhdr_t [DWARF sdwan.h:297]; the following bytes are an inner packet.
type SRHeader struct {
	NextID, LinkCount byte
	Algorithm, PadLen byte
	Links             []uint32
	Inner             []byte
}

func (s SRHeader) Marshal() ([]byte, error) {
	if len(s.Links) > 255 || s.Algorithm > 7 || s.PadLen > 31 {
		return nil, errors.New("invalid SR header")
	}
	b := []byte{PTSegRT, s.NextID, byte(len(s.Links)), s.Algorithm&7 | (s.PadLen&31)<<3}
	for _, v := range s.Links {
		b = append(b, BE32(v)...)
	}
	return append(b, s.Inner...), nil
}
func ParseSRHeader(b []byte) (SRHeader, error) {
	if len(b) < 4 || b[0] != PTSegRT {
		return SRHeader{}, errors.New("invalid SR header")
	}
	n := int(b[2])
	if len(b) < 4+4*n {
		return SRHeader{}, errors.New("short SR header")
	}
	s := SRHeader{NextID: b[1], LinkCount: b[2], Algorithm: b[3] & 7, PadLen: b[3] >> 3}
	s.Links = make([]uint32, n)
	for i := range s.Links {
		s.Links[i] = binary.BigEndian.Uint32(b[4+i*4:])
	}
	s.Inner = append([]byte{}, b[4+4*n:]...)
	return s, nil
}

func (e Echo) Marshal() []byte {
	p := make([]byte, 24)
	binary.LittleEndian.PutUint64(p, e.Tick)
	binary.LittleEndian.PutUint32(p[8:], e.Cur)
	binary.LittleEndian.PutUint32(p[12:], e.Min)
	binary.LittleEndian.PutUint32(p[16:], e.Max)
	return Signed(e.Header, p)
}
func ParseEcho(b []byte) (Echo, error) {
	h, p, e := VerifySigned(b)
	if e != nil {
		return Echo{}, e
	}
	if h.Type != PTEchoReq && h.Type != PTEchoResp {
		return Echo{}, errors.New("not ECHO")
	}
	if len(p) < 24 {
		return Echo{}, errors.New("short echo")
	}
	return Echo{h, binary.LittleEndian.Uint64(p), binary.LittleEndian.Uint32(p[8:]), binary.LittleEndian.Uint32(p[12:]), binary.LittleEndian.Uint32(p[16:]), append([]byte{}, p[24:]...)}, nil
}

// lookup3/jhash, matching the reference's initval=0 algorithm for SR keys.
func JHash(k []byte) uint32 {
	a, b, c := uint32(0x9e3779b9), uint32(0x9e3779b9), uint32(0)
	n := len(k)
	for n >= 12 {
		a += binary.LittleEndian.Uint32(k)
		b += binary.LittleEndian.Uint32(k[4:])
		c += binary.LittleEndian.Uint32(k[8:])
		a, b, c = mix(a, b, c)
		k = k[12:]
		n -= 12
	}
	c += uint32(len(k))
	switch n {
	case 11:
		c += uint32(k[10]) << 24
		fallthrough
	case 10:
		c += uint32(k[9]) << 16
		fallthrough
	case 9:
		c += uint32(k[8]) << 8
		fallthrough
	case 8:
		b += uint32(k[7]) << 24
		fallthrough
	case 7:
		b += uint32(k[6]) << 16
		fallthrough
	case 6:
		b += uint32(k[5]) << 8
		fallthrough
	case 5:
		b += uint32(k[4])
		fallthrough
	case 4:
		a += uint32(k[3]) << 24
		fallthrough
	case 3:
		a += uint32(k[2]) << 16
		fallthrough
	case 2:
		a += uint32(k[1]) << 8
		fallthrough
	case 1:
		a += uint32(k[0])
	}
	_, _, c = final(a, b, c)
	return c
}
func mix(a, b, c uint32) (uint32, uint32, uint32) {
	a -= b
	a -= c
	a ^= c >> 13
	b -= c
	b -= a
	b ^= a << 8
	c -= a
	c -= b
	c ^= b >> 13
	a -= b
	a -= c
	a ^= c >> 12
	b -= c
	b -= a
	b ^= a << 16
	c -= a
	c -= b
	c ^= b >> 5
	a -= b
	a -= c
	a ^= c >> 3
	b -= c
	b -= a
	b ^= a << 10
	c -= a
	c -= b
	c ^= b >> 15
	return a, b, c
}
func final(a, b, c uint32) (uint32, uint32, uint32) {
	c ^= b
	c -= b << 14
	a ^= c
	a -= c >> 11
	b ^= a
	b -= a << 25
	c ^= b
	c -= b >> 16
	a ^= c
	a -= c << 4
	b ^= a
	b -= a >> 14
	c ^= b
	c -= b << 24
	return a, b, c
}
func SRAESKey(links []uint32, password string) []byte {
	raw := make([]byte, 4*len(links))
	for i, v := range links {
		binary.BigEndian.PutUint32(raw[i*4:], v)
	}
	rev := append([]byte{}, raw...)
	for i, j := 0, len(links)-1; i < j; i, j = i+1, j-1 {
		copy(rev[i*4:], raw[j*4:j*4+4])
		copy(rev[j*4:], raw[i*4:i*4+4])
	}
	h := uint32(0)
	if len(links) != 0 {
		h = JHash(raw) + JHash(rev)
	}
	k := make([]byte, 32)
	copy(k, password)
	hb := make([]byte, 4)
	binary.LittleEndian.PutUint32(hb, h)
	for i := len(password); i < 32; i += 4 {
		copy(k[i:], hb)
	}
	return k
}
func AES128ECB(key, data []byte, encrypt bool) []byte {
	if len(key) < 16 || len(data)%16 != 0 {
		return nil
	}
	c, _ := aes.NewCipher(key[:16])
	o := append([]byte{}, data...)
	for i := 0; i < len(o); i += 16 {
		if encrypt {
			c.Encrypt(o[i:i+16], o[i:i+16])
		} else {
			c.Decrypt(o[i:i+16], o[i:i+16])
		}
	}
	return o
}
