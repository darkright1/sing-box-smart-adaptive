//go:build with_iwan

package iwan

import (
	"net/netip"
	"testing"
)

func TestServerPoolAllocatesDistinctUsableAddresses(t *testing.T) {
	runtime := &serverRuntime{pool: netip.MustParsePrefix("10.10.0.0/29"), peers: make(map[string]*serverPeer)}
	first, ok := runtime.allocate()
	if !ok || first == netip.MustParseAddr("10.10.0.0") || first == netip.MustParseAddr("10.10.0.1") || first == netip.MustParseAddr("10.10.0.7") {
		t.Fatalf("unexpected first allocation: %v", first)
	}
	runtime.peers["peer"] = &serverPeer{address: first}
	second, ok := runtime.allocate()
	if !ok || second == first {
		t.Fatalf("allocation reused address: %v", second)
	}
}
