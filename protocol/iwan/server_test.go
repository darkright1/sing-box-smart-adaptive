//go:build with_iwan

package iwan

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	transport "github.com/sagernet/sing-box/transport/iwan"
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

func TestInboundPacketView(t *testing.T) {
	payload := []byte{0x45, 1, 2, 3, 4, 5}
	backing := make([]byte, transport.PacketHeadroom+HeaderLen+len(payload))
	copy(backing[transport.PacketHeadroom+HeaderLen:], payload)
	view := newInboundPacketView(backing, HeaderLen, len(payload))
	defer view.Release()
	if view.Start() != transport.PacketHeadroom+HeaderLen {
		t.Fatalf("unexpected view start: %d", view.Start())
	}
	if !bytes.Equal(view.Bytes(), payload) {
		t.Fatalf("unexpected view payload: %x", view.Bytes())
	}
}

func TestServerPoolAllocatesDistinctUsableAddresses(t *testing.T) {
	runtime := &serverRuntime{pool: netip.MustParsePrefix("10.10.0.0/29"), peers: make(map[netip.AddrPort]*serverPeer)}
	for i := 0; i < 5; i++ {
		address, ok := runtime.allocate()
		if !ok || address == netip.MustParseAddr("10.10.0.0") || address == netip.MustParseAddr("10.10.0.1") || address == netip.MustParseAddr("10.10.0.7") {
			t.Fatalf("unexpected allocation: %v", address)
		}
		runtime.peers[netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(10000+i))] = &serverPeer{address: address}
	}
	if address, ok := runtime.allocate(); ok || address.IsValid() {
		t.Fatalf("expected exhausted pool, got %v", address)
	}
}

func TestServerPeerKeyNormalizesIPv4(t *testing.T) {
	key4, ok := serverPeerKey(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 1234})
	if !ok {
		t.Fatal("IPv4 peer key rejected")
	}
	keyBytes, ok := serverPeerKey(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234})
	if !ok || key4 != keyBytes {
		t.Fatalf("IPv4 key was not stable: %v != %v", key4, keyBytes)
	}
	if _, ok := serverPeerKey(nil); ok {
		t.Fatal("nil peer address accepted")
	}
}
