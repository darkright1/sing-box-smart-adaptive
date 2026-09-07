package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

type managerTestProvider struct {
	tag       string
	closeErr  error
	closeSeen int
	startFn   func()
}

func (p *managerTestProvider) Type() string                             { return "test" }
func (p *managerTestProvider) Tag() string                              { return p.tag }
func (p *managerTestProvider) Outbounds() []adapter.Outbound            { return nil }
func (p *managerTestProvider) Outbound(string) (adapter.Outbound, bool) { return nil, false }
func (p *managerTestProvider) UpdatedAt() time.Time                     { return time.Time{} }
func (p *managerTestProvider) HealthCheck(context.Context) (map[string]uint16, error) {
	return nil, nil
}
func (p *managerTestProvider) RegisterCallback(adapter.ProviderUpdateCallback) *list.Element[adapter.ProviderUpdateCallback] {
	return nil
}
func (p *managerTestProvider) UnregisterCallback(*list.Element[adapter.ProviderUpdateCallback]) {}
func (p *managerTestProvider) StartContext(context.Context, *adapter.HTTPStartContext) error {
	if p.startFn != nil {
		p.startFn()
	}
	return nil
}
func (p *managerTestProvider) Close() error {
	p.closeSeen++
	return p.closeErr
}

var _ adapter.Provider = (*managerTestProvider)(nil)

type managerTestRegistry struct {
	provider adapter.Provider
}

func (managerTestRegistry) OptionTypes() []string            { return []string{"test"} }
func (managerTestRegistry) CreateOptions(string) (any, bool) { return nil, true }
func (r managerTestRegistry) CreateProvider(context.Context, adapter.Router, log.Factory, string, string, any) (adapter.Provider, error) {
	return r.provider, nil
}

var _ adapter.ProviderRegistry = managerTestRegistry{}

func TestManagerCloseReleasesProvidersBeforeStart(t *testing.T) {
	p := &managerTestProvider{tag: "p"}
	m := NewManager(context.Background(), logger.NOP(), nil)
	m.providers = []adapter.Provider{p}
	m.providerByTag[p.Tag()] = p

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if p.closeSeen != 1 {
		t.Fatalf("pre-start provider close count=%d, want 1", p.closeSeen)
	}
	if len(m.Providers()) != 0 {
		t.Fatal("manager retained providers after close")
	}
}

func TestManagerReplacementPublishesNewProviderWhenOldCloseFails(t *testing.T) {
	old := &managerTestProvider{tag: "p", closeErr: errors.New("cleanup failed")}
	newProvider := &managerTestProvider{tag: "p"}
	m := NewManager(context.Background(), logger.NOP(), managerTestRegistry{provider: newProvider})
	m.started = true
	m.stage = adapter.StartStateStarted
	m.providers = []adapter.Provider{old}
	m.providerByTag[old.Tag()] = old

	err := m.Create(context.Background(), nil, nil, "p", "test", nil)
	if err == nil {
		t.Fatal("replacement cleanup error should be reported")
	}
	current, ok := m.Get("p")
	if !ok || current != newProvider {
		t.Fatalf("new provider was not authoritative after old close error: %v %v", current, ok)
	}
	if old.closeSeen != 1 {
		t.Fatalf("old provider close count=%d, want 1", old.closeSeen)
	}
}

func TestManagerProviderStartCanReadManagerWithoutAccessDeadlock(t *testing.T) {
	m := NewManager(context.Background(), logger.NOP(), nil)
	old := &managerTestProvider{tag: "old"}
	m.providers = []adapter.Provider{old}
	m.providerByTag[old.Tag()] = old
	m.started = true
	m.stage = adapter.StartStateStarted
	newProvider := &managerTestProvider{tag: "new"}
	newProvider.startFn = func() {
		if _, ok := m.Get("old"); !ok {
			t.Error("manager lookup failed while provider was starting")
		}
	}
	m.registry = managerTestRegistry{provider: newProvider}
	if err := m.Create(context.Background(), nil, nil, "new", "test", nil); err != nil {
		t.Fatal(err)
	}
}
