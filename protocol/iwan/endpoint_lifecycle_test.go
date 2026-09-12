//go:build with_iwan

package iwan

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestOnDemandIsClientOnly(t *testing.T) {
	client := &Endpoint{options: option.IWANEndpointOptions{Mode: "client", OnDemand: true}}
	if !client.OnDemand() {
		t.Fatal("client on-demand endpoint must advertise OnDemand")
	}
	server := &Endpoint{options: option.IWANEndpointOptions{Mode: "server", OnDemand: true}}
	if server.OnDemand() {
		t.Fatal("server endpoint must not be suspended by outbound reference tracking")
	}
}

func TestOnDemandSuspendWithoutSessionIsSafe(t *testing.T) {
	endpoint := &Endpoint{options: option.IWANEndpointOptions{Mode: "client", OnDemand: true}}
	endpoint.suspend()
	if endpoint.suspended.Load() {
		t.Fatal("an endpoint without a session must remain unsuspended")
	}
}
