package group

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	blist "github.com/sagernet/sing/common/x/list"
)

type fakeProvider struct {
	tag   string
	nodes []adapter.Outbound
}

func (p *fakeProvider) Type() string { return "provider" }
func (p *fakeProvider) Tag() string  { return p.tag }
func (p *fakeProvider) Outbounds() []adapter.Outbound {
	return p.nodes
}
func (p *fakeProvider) Outbound(tag string) (adapter.Outbound, bool) {
	for _, node := range p.nodes {
		if node.Tag() == tag {
			return node, true
		}
	}
	return nil, false
}
func (p *fakeProvider) UpdatedAt() time.Time { return time.Now() }
func (p *fakeProvider) HealthCheck(ctx context.Context) (map[string]uint16, error) {
	return nil, nil
}
func (p *fakeProvider) RegisterCallback(callback adapter.ProviderUpdateCallback) *blist.Element[adapter.ProviderUpdateCallback] {
	return nil
}
func (p *fakeProvider) UnregisterCallback(element *blist.Element[adapter.ProviderUpdateCallback]) {
}

type fakeProviderManager struct {
	providers []adapter.Provider
}

func (m *fakeProviderManager) Providers() []adapter.Provider        { return m.providers }
func (m *fakeProviderManager) Remove(tag string) error              { return nil }
func (m *fakeProviderManager) Start(stage adapter.StartStage) error { return nil }
func (m *fakeProviderManager) PostStart() error                     { return nil }
func (m *fakeProviderManager) PreClose() error                      { return nil }
func (m *fakeProviderManager) Close() error                         { return nil }
func (m *fakeProviderManager) Create(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, providerType string, options any) error {
	return nil
}
func (m *fakeProviderManager) Get(tag string) (adapter.Provider, bool) {
	for _, provider := range m.providers {
		if provider.Tag() == tag {
			return provider, true
		}
	}
	return nil, false
}

type providerTestNode struct {
	adapter.Outbound
	tag string
}

func (n *providerTestNode) Tag() string { return n.tag }

func newTestProviderSource(t *testing.T, options option.GroupCommonOption) (*groupProviderSource, *fakeProviderManager) {
	t.Helper()
	source := newGroupProviderSource(context.Background(), options)
	manager := &fakeProviderManager{providers: []adapter.Provider{
		&fakeProvider{tag: "prov-a", nodes: []adapter.Outbound{
			&providerTestNode{tag: "HK-香港 01"},
			&providerTestNode{tag: "US-美国 01"},
		}},
		&fakeProvider{tag: "prov-b", nodes: []adapter.Outbound{
			&providerTestNode{tag: "HK-香港 02"},
			&providerTestNode{tag: "JP-日本 01"},
		}},
	}}
	source.manager = manager
	return source, manager
}

func mustRegex(t *testing.T, expr string) *badoption.Regexp {
	t.Helper()
	return (*badoption.Regexp)(regexp.MustCompile(expr))
}

func TestGroupProviderSourceIncludeRegex(t *testing.T) {
	source, manager := newTestProviderSource(t, option.GroupCommonOption{
		Providers: []string{"prov-a", "prov-b"},
		Include:   mustRegex(t, `HK|hk|香港|港`),
	})
	if err := source.register(func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	tags, members := source.memberOutbounds("")
	if len(members) != 2 || len(tags) != 2 {
		t.Fatalf("tags=%v members=%d", tags, len(members))
	}
	for _, tag := range tags {
		if tag != "HK-香港 01" && tag != "HK-香港 02" {
			t.Fatalf("include filter leaked %q", tag)
		}
	}
	if len(manager.Providers()) != 2 {
		t.Fatalf("providers registered=%d", len(manager.Providers()))
	}
}

func TestGroupProviderSourceExcludeRegex(t *testing.T) {
	source, _ := newTestProviderSource(t, option.GroupCommonOption{
		UseAllProviders: true,
		Exclude:         mustRegex(t, `US|美国`),
	})
	if err := source.register(func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, members := source.memberOutbounds("")
	if len(members) != 3 {
		t.Fatalf("members=%d, want 3 (US excluded)", len(members))
	}
	for _, member := range members {
		if member.Tag() == "US-美国 01" {
			t.Fatalf("exclude filter leaked %q", member.Tag())
		}
	}
}

func TestGroupProviderSourceIncrementalUpdate(t *testing.T) {
	source, _ := newTestProviderSource(t, option.GroupCommonOption{
		Providers: []string{"prov-a", "prov-b"},
	})
	if err := source.register(func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, first := source.memberOutbounds("")
	_, second := source.memberOutbounds("prov-b")
	if len(first) != 4 || len(second) != 4 {
		t.Fatalf("first=%d second=%d, want 4/4", len(first), len(second))
	}
}
