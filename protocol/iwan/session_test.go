//go:build with_iwan

package iwan

import "testing"

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
