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
	ctx      context.Context
	logger   log.ContextLogger
	registry adapter.ProviderRegistry
	// operation serializes state transitions without extending the manager
	// mutex across provider Start/Close callbacks. Provider implementations are
	// external code and may re-enter the manager or wait on another lifecycle.
	operation     sync.Mutex
	access        sync.Mutex
	closeAccess   sync.Mutex
	closeOnce     map[adapter.Provider]*providerCloseResult
	generation    uint64
	started       bool
	starting      bool
	stage         adapter.StartStage
	providers     []adapter.Provider
	providerByTag map[string]adapter.Provider
	callbacks     list.List[adapter.ProviderManagerUpdateCallback]
}

type providerCloseResult struct {
	once sync.Once
	err  error
}

func NewManager(ctx context.Context, logger logger.ContextLogger, registry adapter.ProviderRegistry) *Manager {
	return &Manager{
		ctx:           ctx,
		logger:        logger,
		registry:      registry,
		providerByTag: make(map[string]adapter.Provider),
		closeOnce:     make(map[adapter.Provider]*providerCloseResult),
	}
}

func (m *Manager) Initialize() {
}

func (m *Manager) Start(stage adapter.StartStage) error {
	m.operation.Lock()
	m.access.Lock()
	if m.starting || m.started && m.stage >= stage {
		m.access.Unlock()
		m.operation.Unlock()
		panic("already started")
	}
	previousStarted := m.started
	previousStage := m.stage
	m.generation++
	generation := m.generation
	m.starting = true
	providers := append([]adapter.Provider(nil), m.providers...)
	if stage == adapter.StartStateStart {
		for _, provider := range providers {
			m.resetCloseState(provider)
		}
	}
	m.access.Unlock()
	m.operation.Unlock()
	if stage == adapter.StartStateStart && len(providers) > 0 {
		startContext := adapter.NewHTTPStartContext()
		attemptedProviders := make([]adapter.Provider, 0, len(providers))
		var startErr error
		for _, provider := range providers {
			attemptedProviders = append(attemptedProviders, provider)
			if err := startProvider(m.ctx, provider, startContext); err != nil {
				startErr = E.Cause(err, stage, " provider/", provider.Type(), "[", provider.Tag(), "]")
				break
			}
		}
		startContext.Close()
		if startErr != nil {
			// Start is transactional: a provider that was started before a later
			// failure must not keep running, and the manager must be retryable.
			for index := len(attemptedProviders) - 1; index >= 0; index-- {
				_ = m.closeProvider(attemptedProviders[index])
			}
			// Close may have changed the manager while external code was running.
			// Restore only our own state in the uncontended case; a concurrent
			// Close already owns cleanup of the providers it detached.
			m.operation.Lock()
			m.access.Lock()
			if m.generation == generation {
				m.starting = false
				m.started = previousStarted
				m.stage = previousStage
			}
			m.access.Unlock()
			m.operation.Unlock()
			return startErr
		}
		return m.commitStart(generation, stage)
	}
	return m.commitStart(generation, stage)
}

func (m *Manager) commitStart(generation uint64, stage adapter.StartStage) error {
	m.operation.Lock()
	defer m.operation.Unlock()
	m.access.Lock()
	defer m.access.Unlock()
	if m.generation != generation {
		return E.New("provider manager changed while starting stage ", stage)
	}
	m.starting = false
	m.started = true
	m.stage = stage
	return nil
}

func (m *Manager) Close() error {
	m.operation.Lock()
	monitor := taskmonitor.New(m.logger, C.StopTimeout)
	m.access.Lock()
	m.generation++
	m.starting = false
	m.started = false
	m.stage = adapter.StartStateInitialize
	providers := m.providers
	m.providers = nil
	m.providerByTag = make(map[string]adapter.Provider)
	m.access.Unlock()
	m.operation.Unlock()
	m.notifyProviderCallbacks()
	var err error
	for _, provider := range providers {
		if _, isCloser := provider.(io.Closer); isCloser {
			monitor.Start("close provider/", provider.Type(), "[", provider.Tag(), "]")
			err = E.Append(err, m.closeProvider(provider), func(err error) error {
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
	m.operation.Lock()
	m.access.Lock()
	provider, found := m.providerByTag[tag]
	if !found {
		m.access.Unlock()
		m.operation.Unlock()
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
	m.access.Unlock()
	m.operation.Unlock()
	m.notifyProviderCallbacks()
	return m.closeProvider(provider)
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logFactory log.Factory, tag string, providerType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}

	provider, err := m.registry.CreateProvider(ctx, router, logFactory, tag, providerType, options)
	if err != nil {
		return err
	}
	m.resetCloseState(provider)
	m.operation.Lock()
	m.access.Lock()
	started := m.started
	stage := m.stage
	existsProvider := m.providerByTag[tag]
	generation := m.generation
	m.access.Unlock()
	m.operation.Unlock()

	// A replacement is prepared completely before it becomes authoritative.
	// Start is intentionally outside the manager lock; a failed start leaves the
	// old provider untouched and the newly-created provider is closed.
	if started && stage >= adapter.StartStateStart {
		startContext := adapter.NewHTTPStartContext()
		err = startProvider(m.ctx, provider, startContext)
		startContext.Close()
		if err != nil {
			_ = m.closeProvider(provider)
			return E.Cause(err, "start provider/", provider.Type(), "[", provider.Tag(), "]")
		}
	}

	m.operation.Lock()
	m.access.Lock()
	// Revalidate both the manager generation and the observed tag entry. A
	// concurrent Close or replacement may have completed while the new
	// provider was starting; never publish into that newer state.
	currentProvider := m.providerByTag[tag]
	if m.generation != generation || currentProvider != existsProvider {
		m.access.Unlock()
		m.operation.Unlock()
		_ = m.closeProvider(provider)
		return E.New("provider changed while creating: ", tag)
	}
	if existsProvider != nil {
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
	m.operation.Unlock()
	m.notifyProviderCallbacks()
	if existsProvider != nil {
		// Closing an old provider is best-effort after publication. A partial
		// cleanup failure must never roll the authoritative view back to a
		// provider whose resources may already be closed.
		if err = m.closeProvider(existsProvider); err != nil {
			// Publication already committed. Cleanup failure is a warning, not a
			// provisioning failure that would invite a destructive retry.
			if m.logger != nil {
				m.logger.Warn("close replaced provider/", existsProvider.Type(), "[", existsProvider.Tag(), "]: ", err)
			}
		}
	}
	return nil
}

// closeProvider makes provider cleanup idempotent across lifecycle races. A
// provider may be selected for cleanup by a failed Start while a concurrent
// Close/Remove is already tearing the manager down; the external Close method
// must still run at most once.
func (m *Manager) closeProvider(provider adapter.Provider) error {
	if provider == nil {
		return nil
	}
	m.closeAccess.Lock()
	result := m.closeOnce[provider]
	if result == nil {
		result = new(providerCloseResult)
		m.closeOnce[provider] = result
	}
	m.closeAccess.Unlock()
	result.once.Do(func() {
		result.err = common.Close(provider)
	})
	return result.err
}

func (m *Manager) resetCloseState(provider adapter.Provider) {
	if provider == nil {
		return
	}
	m.closeAccess.Lock()
	delete(m.closeOnce, provider)
	m.closeAccess.Unlock()
}

func startProvider(ctx context.Context, provider adapter.Provider, startContext *adapter.HTTPStartContext) error {
	if contextStarter, ok := provider.(interface {
		StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error
	}); ok {
		return contextStarter.StartContext(ctx, startContext)
	}
	return nil
}
