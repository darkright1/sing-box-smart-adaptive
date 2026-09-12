//go:build with_iwan

package iwan

import (
	"fmt"
	"net/netip"
	"testing"
)

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
