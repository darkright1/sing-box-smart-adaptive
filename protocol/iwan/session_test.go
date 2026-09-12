//go:build with_iwan

package iwan

import (
	"net/netip"
	"testing"
	"time"
)

func TestSessionRejectsDataBeforeOpenAck(t *testing.T) {
	s, err := NewSession(SessionOptions{Client: true, Username: "u", Password: "p", MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	frame := BuildData(Header{SID: 1, Token: 2}, []byte("x"), "u", "p", false)
	if _, _, err = s.Handle(frame); err == nil {
		t.Fatal("expected not-ready error")
	}
}

func TestSessionCopiesLinksAndRequiresAck(t *testing.T) {
	links := []uint32{7, 9}
	s, err := NewSession(SessionOptions{Client: true, Username: "u", Password: "p", MTU: 1400, Links: links})
	if err != nil {
		t.Fatal(err)
	}
	links[0] = 99
	open, err := s.Open()
	if err != nil || len(open) == 0 {
		t.Fatalf("open: %v", err)
	}
	if s.Ready() {
		t.Fatal("session became ready without OPENACK")
	}
}

func TestSessionRejectsMismatchedOpenAck(t *testing.T) {
	s, err := NewSession(SessionOptions{Client: true, Username: "u", Password: "p", MTU: 1400})
	if err != nil {
		t.Fatal(err)
	}
	open, err := s.Open()
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHeader(open)
	if err != nil {
		t.Fatal(err)
	}
	h.SID++
	ack, err := BuildOpenAck(h, AckFields{MTU: 1400, IP: 0x0aff0002, Gateway: 0x0aff0001})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Handle(ack); err == nil {
		t.Fatal("expected OPENACK identity mismatch")
	}
}

func TestSessionSourceRoutingRoundTrip(t *testing.T) {
	s, err := NewSession(SessionOptions{Client: true, Username: "u", Password: "p", SRPassword: "sr", MTU: 1400, Links: []uint32{7, 9}})
	if err != nil {
		t.Fatal(err)
	}
	inner := Signed(Header{Type: PTData, SID: 9, Token: 11}, []byte("payload"))
	wire, err := s.Wrap(inner)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) <= len(inner) || wire[0] != PTSegRT {
		t.Fatalf("unexpected SR wire packet length=%d", len(wire))
	}
	out, err := s.Unwrap(wire)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(inner) {
		t.Fatalf("SR round trip mismatch")
	}
}

func TestServerReapsIdlePeer(t *testing.T) {
	peer := &serverPeer{}
	peer.lastSeen.Store(time.Now().Add(-time.Minute).UnixNano())
	runtime := &serverRuntime{peers: map[string]*serverPeer{"idle": peer}, pool: netip.MustParsePrefix("10.10.0.0/29")}
	runtime.reap(time.Now())
	if len(runtime.peers) != 0 {
		t.Fatal("idle peer was not reaped")
	}
}
