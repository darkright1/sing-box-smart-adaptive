//go:build with_iwan

package iwan

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestPacketDestination(t *testing.T) {
	ipv4 := make([]byte, 20)
	ipv4[0] = 0x45
	ipv4[16], ipv4[17], ipv4[18], ipv4[19] = 10, 10, 0, 2
	if got, ok := packetDestination(ipv4); !ok || got != netip.MustParseAddr("10.10.0.2") {
		t.Fatalf("unexpected IPv4 destination: %v, %v", got, ok)
	}
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	copy(ipv6[24:], netip.MustParseAddr("2001:db8::2").AsSlice())
	if got, ok := packetDestination(ipv6); !ok || got != netip.MustParseAddr("2001:db8::2") {
		t.Fatalf("unexpected IPv6 destination: %v, %v", got, ok)
	}
	for _, packet := range [][]byte{nil, {0x45}, make([]byte, 19), {0x70}} {
		if got, ok := packetDestination(packet); ok || got.IsValid() {
			t.Fatalf("malformed packet accepted: %x -> %v, %v", packet, got, ok)
		}
	}
}

func TestServerPoolAllocatesDistinctUsableAddresses(t *testing.T) {
	runtime := &serverRuntime{pool: netip.MustParsePrefix("10.10.0.0/29"), peers: make(map[string]*serverPeer)}
	for i := 0; i < 5; i++ {
		address, ok := runtime.allocate()
		if !ok || address == netip.MustParseAddr("10.10.0.0") || address == netip.MustParseAddr("10.10.0.1") || address == netip.MustParseAddr("10.10.0.7") {
			t.Fatalf("unexpected allocation: %v", address)
		}
		runtime.peers[fmt.Sprintf("peer-%d", i)] = &serverPeer{address: address}
	}
	if address, ok := runtime.allocate(); ok || address.IsValid() {
		t.Fatalf("expected exhausted pool, got %v", address)
	}
}
