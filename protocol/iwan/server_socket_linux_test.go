//go:build with_iwan && linux

package iwan

import (
	"net"
	"testing"
)

func TestConfiguredIWANServerSocketReadersIsBounded(t *testing.T) {
	if got := configuredIWANServerSocketReaders(0); got != 1 {
		t.Fatalf("zero readers must fall back to one, got %d", got)
	}
	if got := configuredIWANServerSocketReaders(99); got != maxIWANServerSocketReaders {
		t.Fatalf("readers must be capped at %d, got %d", maxIWANServerSocketReaders, got)
	}
	if got := configuredIWANServerSocketReaders(-1); got != 1 {
		t.Fatalf("negative readers must fall back to one, got %d", got)
	}
}

func TestListenIWANServerSocketsFallsBackOrBindsReusePortSet(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().(*net.UDPAddr)
	_ = probe.Close()
	conns, err := listenIWANServerSockets(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer closeIWANServerSockets(conns)
	if len(conns) != 1 && len(conns) != 2 {
		t.Fatalf("unexpected reader fallback count: %d", len(conns))
	}
	if len(conns) == 2 {
		for _, conn := range conns {
			if conn.LocalAddr().(*net.UDPAddr).Port != addr.Port {
				t.Fatalf("reuse-port socket changed port: want %d", addr.Port)
			}
		}
	}
}
