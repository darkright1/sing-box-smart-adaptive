package parser

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

type parserOutboundRegistry struct{}

func (parserOutboundRegistry) OptionTypes() []string { return []string{C.TypeSOCKS} }

func (parserOutboundRegistry) CreateOptions(protocol string) (any, bool) {
	if protocol != C.TypeSOCKS {
		return nil, false
	}
	return new(option.SOCKSOutboundOptions), true
}

type parserEndpointRegistry struct{}

func (parserEndpointRegistry) OptionTypes() []string { return []string{C.TypeWireGuard} }

func (parserEndpointRegistry) CreateOptions(protocol string) (any, bool) {
	if protocol != C.TypeWireGuard {
		return nil, false
	}
	return new(option.WireGuardEndpointOptions), true
}

func parserContext() context.Context {
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), parserOutboundRegistry{})
	return service.ContextWith[option.EndpointOptionsRegistry](ctx, parserEndpointRegistry{})
}

func TestParseBoxSubscriptionSkipsUnsupportedAndMalformedMembers(t *testing.T) {
	ctx := parserContext()
	outbounds, endpoints, err := ParseSubscription(ctx, `{
  "outbounds": [
    {"type":"socks", "tag":"valid", "server":"127.0.0.1", "server_port":1080},
    {"type":"made-up", "tag":"unsupported", "server":"127.0.0.1", "server_port":1080},
    {"type":"socks", "tag":"malformed", "server_port":"not-a-number"},
    {"type":"selector", "tag":"group", "outbounds":["valid"]}
  ]
}`, nil, nil, nil, "test-provider")
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 0 || len(outbounds) != 1 || outbounds[0].Tag != "valid" {
		t.Fatalf("outbounds=%+v endpoints=%+v", outbounds, endpoints)
	}
}

func TestParseClashSubscriptionSkipsUnsupportedAndMalformedMembers(t *testing.T) {
	outbounds, endpoints, err := ParseClashSubscription(context.WithValue(context.Background(), providerTagContextKey{}, "test-provider"), `
proxies:
  - name: valid
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: unsupported
    type: wireguard-lite
    server: 127.0.0.1
    port: 1080
  - name: malformed
    type: vmess
    server: 127.0.0.1
    port: nope
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 0 || len(outbounds) != 1 || outbounds[0].Tag != "valid" {
		t.Fatalf("outbounds=%+v endpoints=%+v", outbounds, endpoints)
	}
}

func TestFilterSupportedMembersUsesBuildRegistry(t *testing.T) {
	ctx := parserContext()
	outbounds, endpoints := filterSupportedMembers(ctx, []option.Outbound{
		{Type: C.TypeSOCKS, Tag: "valid", Options: new(option.SOCKSOutboundOptions)},
		{Type: "not-built", Tag: "unsupported", Options: new(option.SOCKSOutboundOptions)},
		{Type: C.TypeSOCKS, Tag: "nil-options"},
	}, []option.Endpoint{
		{Type: C.TypeWireGuard, Tag: "wg", Options: new(option.WireGuardEndpointOptions)},
		{Type: "not-built", Tag: "bad"},
	}, "test-provider")
	if len(outbounds) != 1 || len(endpoints) != 1 {
		t.Fatalf("outbounds=%+v endpoints=%+v", outbounds, endpoints)
	}
}

func TestFilterSupportedMembersAlwaysDropsNilOptions(t *testing.T) {
	outbounds, endpoints := filterSupportedMembers(context.Background(), []option.Outbound{
		{Type: C.TypeSOCKS, Tag: "broken"},
	}, []option.Endpoint{{Type: C.TypeWireGuard, Tag: "broken-endpoint"}}, "test")
	if len(outbounds) != 0 || len(endpoints) != 0 {
		t.Fatalf("nil option members must be discarded without registries: outbounds=%d endpoints=%d", len(outbounds), len(endpoints))
	}
}
