package provider

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

var _ adapter.ProviderManager = (*Manager)(nil)
var _ adapter.ProviderManagerObserver = (*Manager)(nil)

type Manager struct {
	ctx           context.Context
	logger        log.ContextLogger
	registry      adapter.ProviderRegistry
	access        sync.Mutex
	started       bool
	stage         adapter.StartStage
	providers     []adapter.Provider
	providerByTag map[string]adapter.Provider
	callbacks     list.List[adapter.ProviderManagerUpdateCallback]
}

func NewManager(ctx context.Context, logger logger.ContextLogger, registry adapter.ProviderRegistry) *Manager {
	return &Manager{
		ctx:           ctx,
		logger:        logger,
		registry:      registry,
		providerByTag: make(map[string]adapter.Provider),
	}
}

func (m *Manager) Initialize() {
}

func (m *Manager) Start(stage adapter.StartStage) error {
	m.access.Lock()
	if m.started && m.stage >= stage {
		panic("already started")
	}
	m.started = true
	m.stage = stage
	providers := m.providers
	m.access.Unlock()
	if stage == adapter.StartStateStart && len(providers) > 0 {
		startContext := adapter.NewHTTPStartContext()
		defer startContext.Close()
		for _, provider := range providers {
			if contextStarter, ok := provider.(interface {
				StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error
			}); ok {
				err := contextStarter.StartContext(m.ctx, startContext)
				if err != nil {
					return E.Cause(err, stage, " provider/", provider.Type(), "[", provider.Tag(), "]")
				}
			}
		}
		return nil
	}
	return nil
}

func (m *Manager) Close() error {
	monitor := taskmonitor.New(m.logger, C.StopTimeout)
	m.access.Lock()
	if !m.started {
		m.access.Unlock()
		return nil
	}
	m.started = false
	providers := m.providers
	m.providers = nil
	m.providerByTag = make(map[string]adapter.Provider)
	m.access.Unlock()
	m.notifyProviderCallbacks()
	var err error
	for _, provider := range providers {
		if closer, isCloser := provider.(io.Closer); isCloser {
			monitor.Start("close provider/", provider.Type(), "[", provider.Tag(), "]")
			err = E.Append(err, closer.Close(), func(err error) error {
				return E.Cause(err, "close provider/", provider.Type(), "[", provider.Tag(), "]")
			})
			monitor.Finish()
		}
	}
	return nil
}

func (m *Manager) Providers() []adapter.Provider {
	m.access.Lock()
	defer m.access.Unlock()
	return append([]adapter.Provider(nil), m.providers...)
}

func (m *Manager) RegisterProviderCallback(callback adapter.ProviderManagerUpdateCallback) *list.Element[adapter.ProviderManagerUpdateCallback] {
	m.access.Lock()
	defer m.access.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *Manager) UnregisterProviderCallback(element *list.Element[adapter.ProviderManagerUpdateCallback]) {
	m.access.Lock()
	defer m.access.Unlock()
	m.callbacks.Remove(element)
}

func (m *Manager) notifyProviderCallbacks() {
	m.access.Lock()
	callbacks := make([]adapter.ProviderManagerUpdateCallback, 0, m.callbacks.Len())
	for element := m.callbacks.Front(); element != nil; element = element.Next() {
		callbacks = append(callbacks, element.Value)
	}
	m.access.Unlock()
	for _, callback := range callbacks {
		callback()
	}
}

func (m *Manager) Get(tag string) (adapter.Provider, bool) {
	m.access.Lock()
	provider, found := m.providerByTag[tag]
	m.access.Unlock()
	return provider, found
}

func (m *Manager) Remove(tag string) error {
	m.access.Lock()
	provider, found := m.providerByTag[tag]
	if !found {
		m.access.Unlock()
		return os.ErrInvalid
	}
	delete(m.providerByTag, tag)
	index := common.Index(m.providers, func(it adapter.Provider) bool {
		return it == provider
	})
	if index == -1 {
		panic("invalid provider index")
	}
	m.providers = append(m.providers[:index], m.providers[index+1:]...)
	started := m.started
	m.access.Unlock()
	m.notifyProviderCallbacks()
	if started {
		return common.Close(provider)
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, providerType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}

	provider, err := m.registry.CreateProvider(ctx, router, logFactory, tag, providerType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	if m.started {
		if m.stage >= adapter.StartStateStart {
			if contextStarter, ok := provider.(interface {
				StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error
			}); ok {
				startContext := adapter.NewHTTPStartContext()
				err = contextStarter.StartContext(m.ctx, startContext)
				startContext.Close()
				if err != nil {
					m.access.Unlock()
					_ = common.Close(provider)
					return E.Cause(err, "start provider/", provider.Type(), "[", provider.Tag(), "]")
				}
			}
		}
	}
	if existsProvider, loaded := m.providerByTag[tag]; loaded {
		if m.started {
			err = common.Close(existsProvider)
			if err != nil {
				m.access.Unlock()
				_ = common.Close(provider)
				return E.Cause(err, "close provider", provider.Type(), "[", existsProvider.Tag(), "]")
			}
		}
		existsIndex := common.Index(m.providers, func(it adapter.Provider) bool {
			return it == existsProvider
		})
		if existsIndex == -1 {
			panic("invalid provider index")
		}
		m.providers = append(m.providers[:existsIndex], m.providers[existsIndex+1:]...)
	}
	m.providers = append(m.providers, provider)
	m.providerByTag[tag] = provider
	m.access.Unlock()
	m.notifyProviderCallbacks()
	return nil
}
