//go:build with_iwan

package iwan

import (
	"bytes"
	"sync"
	"testing"
)

func TestProtocolVectors(t *testing.T) {
	h := Header{PTOpenAck, 1, 0x1234, 0x89abcdef}
	b := Signed(h, []byte("x"))
	if _, p, e := VerifySigned(b); e != nil || string(p) != "x" {
		t.Fatal(e)
	}
	ts := []TLV{{3, BE16(1400)}, {1, []byte("user")}, {8, []byte{1}}}
	enc, _ := EncodeTLVs(ts)
	got, e := DecodeTLVs(enc)
	if e != nil || len(got) != 3 || !bytes.Equal(got[1].Value, []byte("user")) {
		t.Fatal(e)
	}
	for _, v := range []int{0, 1, 15, 2047} {
		fh := Header{PTIPFrag, 0, h.SID, h.Token}
		f := Frag{fh, 7, v == 2047, uint16(v), uint16(v), bytes.Repeat([]byte{2}, v)}
		x, e := f.Marshal()
		if e != nil {
			t.Fatal(e)
		}
		q, e := ParseFrag(x)
		if e != nil || q.Length != uint16(v) {
			t.Fatal(e)
		}
		view, e := ParseFragView(x)
		if e != nil || !bytes.Equal(view.Payload, q.Payload) {
			t.Fatal(e)
		}
	}
	p := PasswordCipher("u", "secret")
	s, _ := PasswordDecrypt("u", p)
	if s != "secret" {
		t.Fatal(s)
	}
	d := []byte("hello iwan")
	if !bytes.Equal(d, XORData("u", "p", XORData("u", "p", d))) {
		t.Fatal("xor")
	}
	echo := Echo{Header{PTEchoReq, 0, 1, 2}, 3, 4, 5, 6, nil}
	if _, x := ParseEcho(echo.Marshal()); x != nil {
		t.Fatal(x)
	}
}
func TestAESRoundTrip(t *testing.T) {
	d := []byte("0123456789abcdef0123456789abcdef")
	x := AES128ECB([]byte("0123456789abcdef"), d, true)
	if !bytes.Equal(AES128ECB([]byte("0123456789abcdef"), x, false), d) {
		t.Fatal("aes")
	}
}

func TestWirePacketPoolRoundTrip(t *testing.T) {
	h := Header{SID: 7, Token: 11}
	payload := []byte("pooled iwan data")
	packet, pooled := buildDataWithKeyPooled(h, payload, xorCredentialKey("u", "p"), false)
	if pooled == nil {
		t.Fatal("MTU-sized packet was not pooled")
	}
	if _, got, err := ParseData(packet); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("pooled packet round trip failed: %v", err)
	}
	classCap := cap(packet)
	releaseWirePacket(packet, pooled)
	if classCap < len(payload)+HeaderLen {
		t.Fatalf("invalid pooled capacity %d", classCap)
	}
}

func TestFragmentDataPooledMatchesWireFormat(t *testing.T) {
	h := Header{Type: PTData, Encrypt: 1, SID: 7, Token: 11}
	payload := make([]byte, 1500)
	for i := range payload {
		payload[i] = byte(i)
	}
	want, err := FragmentData(h, payload, 700, 19)
	if err != nil || len(want) != 2 {
		t.Fatalf("plain fragmentation: %v", err)
	}
	first, firstPool, second, secondPool, err := FragmentDataPooled(h, payload, 700, 19)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseWirePacket(first, firstPool)
	defer releaseWirePacket(second, secondPool)
	if !bytes.Equal(first, want[0]) || !bytes.Equal(second, want[1]) {
		t.Fatal("pooled fragmentation changed the wire format")
	}
	if got, err := ParseFrag(first); err != nil || got.Offset != 0 || got.EOP {
		t.Fatalf("first fragment parse: %v", err)
	}
	if got, err := ParseFrag(second); err != nil || !got.EOP || int(got.Offset)+len(got.Payload) != len(payload) {
		t.Fatalf("last fragment parse: %v", err)
	}
}

func TestSRRoundTripAndKeyPadding(t *testing.T) {
	inner := BuildData(Header{SID: 4, Token: 5}, []byte("payload that crosses one AES block"), "u", "p", false)
	wrapped, err := WrapSR(inner, []uint32{7, 9}, "123456789012345678901234567890", 1)
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnwrapSR(wrapped, []uint32{7, 9}, "123456789012345678901234567890")
	if err != nil || !bytes.Equal(out, inner) {
		t.Fatalf("sr round trip: %v", err)
	}
}

func TestFragReassemblerConcurrentAccess(t *testing.T) {
	r := NewFragReassembler()
	first := Frag{Header: Header{Type: PTIPFrag}, ID: 9, Offset: 0, Length: 3, Payload: []byte("abc")}
	last := Frag{Header: first.Header, ID: 9, EOP: true, Offset: 3, Length: 3, Payload: []byte("def")}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		now := int64(i + 1)
		go func() { defer wg.Done(); _, _ = r.Add(first, now) }()
		go func() { defer wg.Done(); _, _ = r.Add(last, now) }()
	}
	wg.Wait()
}

func TestFragReassemblerBoundsPendingState(t *testing.T) {
	r := NewFragReassembler()
	for id := uint32(0); id < IWAN_FRAG_PENDING_MAX+32; id++ {
		_, err := r.Add(Frag{Header: Header{Type: PTIPFrag}, ID: id, Offset: 0, Length: 1, Payload: []byte{byte(id)}}, int64(id+1))
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := len(r.pending); got > IWAN_FRAG_PENDING_MAX {
		t.Fatalf("pending fragment state exceeded bound: %d", got)
	}
}

func FuzzPacketParsersNeverPanic(f *testing.F) {
	f.Add([]byte{0x13, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x25, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseHeader(b)
		_, _, _ = VerifySigned(b)
		_, _ = DecodeTLVs(b)
		_, _ = ParseFrag(b)
		_, _ = ParseSRHeader(b)
		_, _ = ParseEcho(b)
	})
}
