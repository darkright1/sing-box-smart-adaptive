//go:build with_iwan && linux

package iwan

import "testing"

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
