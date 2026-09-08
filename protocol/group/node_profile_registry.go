package group

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

const nodeProfileRegistryLimit = 8192

var errSharedNodeProbeFailed = errors.New("shared node probe failed")
var errSharedNodeProbeDeferred = errors.New("shared node probe deferred")

type nodeProfileResult struct {
	delay       uint16
	success     bool
	completedAt time.Time
	nextProbeAt time.Time
	successes   uint8
	failures    uint8
	deferred    bool
}

type nodeProfileEntry struct {
	result   nodeProfileResult
	inflight bool
	done     chan struct{}
}

type nodeProfileRegistry struct {
	ctx     context.Context
	cancel  context.CancelFunc
	access  sync.Mutex
	entries map[string]*nodeProfileEntry
	// active serializes different probe tracks for the same endpoint. The
	// result cache remains track-specific, but TCP and UDP must not create
	// simultaneous upstream health traffic for one physical node.
	active          map[string]chan struct{}
	probe           func(context.Context, string, adapter.Outbound) (uint16, error)
	slots           chan struct{}
	activeGroups    atomic.Uint32
	completedProbes atomic.Uint64
	closeOnce       sync.Once
}

func (r *nodeProfileRegistry) registerSmartScheduler() time.Duration {
	if r == nil {
		return 0
	}
	order := r.activeGroups.Add(1) - 1
	return time.Duration(min(order, uint32(4))) * 15 * time.Second
}

func (r *nodeProfileRegistry) releaseSmartScheduler() {
	if r == nil {
		return
	}
	r.activeGroups.Add(^uint32(0))
}

type nodeProfileRegistryReference struct {
	registry *nodeProfileRegistry
	refs     int
}

var nodeProfileRegistries struct {
	sync.Mutex
	byProcess map[<-chan struct{}]*nodeProfileRegistryReference
}

func acquireGroupProfileRegistry(ctx context.Context) (*nodeProfileRegistry, func()) {
	processKey := ctx.Done()
	if processKey == nil {
		registry := newNodeProfileRegistry(ctx)
		return registry, registry.close
	}
	nodeProfileRegistries.Lock()
	if nodeProfileRegistries.byProcess == nil {
		nodeProfileRegistries.byProcess = make(map[<-chan struct{}]*nodeProfileRegistryReference)
	}
	reference := nodeProfileRegistries.byProcess[processKey]
	if reference == nil {
		reference = &nodeProfileRegistryReference{registry: newNodeProfileRegistry(ctx)}
		nodeProfileRegistries.byProcess[processKey] = reference
		go func(key <-chan struct{}, owned *nodeProfileRegistryReference) {
			<-key
			nodeProfileRegistries.Lock()
			if nodeProfileRegistries.byProcess[key] == owned {
				delete(nodeProfileRegistries.byProcess, key)
			}
			nodeProfileRegistries.Unlock()
			owned.registry.close()
		}(processKey, reference)
	}
	reference.refs++
	registry := reference.registry
	nodeProfileRegistries.Unlock()
	var once sync.Once
	return registry, func() {
		once.Do(func() {
			nodeProfileRegistries.Lock()
			current := nodeProfileRegistries.byProcess[processKey]
			if current == reference {
				current.refs--
				// The registry belongs to the process context, not to any one
				// strategy group. Keeping it alive at zero group references lets a
				// reload inherit the same endpoint evidence without retaining group
				// objects; process cancellation performs the final cleanup.
			}
			nodeProfileRegistries.Unlock()
		})
	}
}

func acquireSmartProfileRegistry(ctx context.Context) (*nodeProfileRegistry, func()) {
	registry, releaseReference := acquireGroupProfileRegistry(ctx)
	var once sync.Once
	return registry, func() {
		once.Do(func() {
			registry.releaseSmartScheduler()
			releaseReference()
		})
	}
}

func newNodeProfileRegistry(parent context.Context) *nodeProfileRegistry {
	ctx, cancel := context.WithCancel(parent)
	return &nodeProfileRegistry{
		ctx:     ctx,
		cancel:  cancel,
		entries: make(map[string]*nodeProfileEntry),
		active:  make(map[string]chan struct{}),
		slots:   make(chan struct{}, 4),
		probe: func(ctx context.Context, link string, outbound adapter.Outbound) (uint16, error) {
			return urltest.URLTest(ctx, link, outbound)
		},
	}
}

func nodeProfileKey(identity, probeURL string, timeout time.Duration) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(identity))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(probeURL))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(timeout.String()))
	return hex.EncodeToString(digest.Sum(nil))
}

func (r *nodeProfileRegistry) dead(key string) bool {
	if r == nil || key == "" {
		return false
	}
	r.access.Lock()
	defer r.access.Unlock()
	entry := r.entries[key]
	if entry == nil || entry.inflight || entry.result.success || entry.result.failures < 3 {
		return false
	}
	// Dead is a temporary breaker state. Once the cadence deadline is reached,
	// the next caller is allowed to run a half-open recovery probe.
	return !entry.result.nextProbeAt.IsZero() && time.Now().Before(entry.result.nextProbeAt)
}

func (r *nodeProfileRegistry) snapshot(key string) (nodeProfileResult, bool) {
	if r == nil || key == "" {
		return nodeProfileResult{}, false
	}
	r.access.Lock()
	defer r.access.Unlock()
	entry := r.entries[key]
	if entry == nil || entry.inflight || entry.result.completedAt.IsZero() || entry.result.deferred {
		return nodeProfileResult{}, false
	}
	return entry.result, true
}

func (r *nodeProfileRegistry) recordPassive(key string, success bool, delay, failureTTL time.Duration) {
	if r == nil || key == "" {
		return
	}
	now := time.Now()
	r.access.Lock()
	entry := r.entries[key]
	if entry == nil {
		entry = new(nodeProfileEntry)
		r.entries[key] = entry
	}
	if entry.inflight {
		r.access.Unlock()
		return
	}
	if success {
		delete(r.entries, key)
		r.access.Unlock()
		return
	}
	if failureTTL <= 0 {
		failureTTL = 30 * time.Second
	}
	entry.result = nodeProfileResult{
		success:     false,
		completedAt: now,
		nextProbeAt: now.Add(failureTTL),
		failures:    min(entry.result.failures+1, uint8(3)),
	}
	r.pruneLocked(now)
	r.access.Unlock()
}

func (r *nodeProfileRegistry) passiveFailureActive(key string) bool {
	result, loaded := r.snapshot(key)
	return loaded && !result.success && time.Now().Before(result.nextProbeAt)
}

func nodeProfileCadence(success bool, successes, failures uint8) time.Duration {
	if success {
		switch successes {
		case 0, 1:
			return 5 * time.Minute
		case 2:
			return 15 * time.Minute
		default:
			return 30 * time.Minute
		}
	}
	switch failures {
	case 0, 1:
		return 30 * time.Second
	case 2:
		return time.Minute
	default:
		return 5 * time.Minute
	}
}

func (r *nodeProfileRegistry) run(ctx context.Context, key, probeURL string, timeout, ttl time.Duration, candidate adapter.Outbound) (uint16, error) {
	delay, err, _ := r.runWithMetaForEndpoint(ctx, key, key, probeURL, timeout, ttl, candidate)
	return delay, err
}

// runWithMeta is the normal URLTest path with an observation freshness bit.
// A cached result is useful for answering a caller, but it is not a new
// network sample and must not reset a local breaker or inflate confidence.
// A waiter joined to an in-flight probe receives fresh=true because that
// probe completed during this call and may be recorded once by its group.
func (r *nodeProfileRegistry) runWithMeta(ctx context.Context, key, probeURL string, timeout, ttl time.Duration, candidate adapter.Outbound) (uint16, error, bool) {
	return r.runWithMetaForEndpoint(ctx, key, key, probeURL, timeout, ttl, candidate)
}

func (r *nodeProfileRegistry) runWithMetaForEndpoint(ctx context.Context, endpointKey, key, probeURL string, timeout, ttl time.Duration, candidate adapter.Outbound) (uint16, error, bool) {
	if r == nil {
		return 0, errSharedNodeProbeFailed, false
	}
	return r.runProbeMode(ctx, endpointKey, key, timeout, ttl, false, func(probeCtx context.Context) (uint16, error) {
		return r.probe(probeCtx, probeURL, candidate)
	})
}

// runRecovery performs one bounded half-open trial when every candidate in a
// Smart context is currently open. It bypasses the normal cadence cache, but
// still shares the per-endpoint single-flight lock and admission slots.
func (r *nodeProfileRegistry) runRecovery(ctx context.Context, key string, timeout, ttl time.Duration, probe func(context.Context) (uint16, error)) (uint16, error) {
	delay, err, _ := r.runProbeModeInternal(ctx, key, key, timeout, ttl, true, true, probe)
	return delay, err
}

func (r *nodeProfileRegistry) runRecoveryForEndpoint(ctx context.Context, endpointKey, key string, timeout, ttl time.Duration, probe func(context.Context) (uint16, error)) (uint16, error) {
	delay, err, _ := r.runProbeModeInternal(ctx, endpointKey, key, timeout, ttl, true, true, probe)
	return delay, err
}

// runProbe is the shared single-flight admission path for every probe kind.
// URLTest and UDP reachability use the same endpoint key, so aliases and
// multiple Smart groups cannot open duplicate probes for one endpoint.
func (r *nodeProfileRegistry) runProbe(ctx context.Context, key string, timeout, ttl time.Duration, probe func(context.Context) (uint16, error)) (uint16, error) {
	delay, err, _ := r.runProbeMode(ctx, key, key, timeout, ttl, false, probe)
	return delay, err
}

func (r *nodeProfileRegistry) runProbeForEndpoint(ctx context.Context, endpointKey, key string, timeout, ttl time.Duration, probe func(context.Context) (uint16, error)) (uint16, error) {
	delay, err, _ := r.runProbeMode(ctx, endpointKey, key, timeout, ttl, false, probe)
	return delay, err
}

func (r *nodeProfileRegistry) runProbeMode(ctx context.Context, endpointKey, key string, timeout, ttl time.Duration, force bool, probe func(context.Context) (uint16, error)) (uint16, error, bool) {
	return r.runProbeModeInternal(ctx, endpointKey, key, timeout, ttl, force, false, probe)
}

func (r *nodeProfileRegistry) runProbeModeInternal(ctx context.Context, endpointKey, key string, timeout, ttl time.Duration, force, retryAfterInflight bool, probe func(context.Context) (uint16, error)) (uint16, error, bool) {
	if r == nil || probe == nil {
		return 0, errSharedNodeProbeFailed, false
	}
	if ctx.Err() != nil {
		return 0, ctx.Err(), false
	}
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err(), false
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	now := time.Now()
	r.access.Lock()
	if r.active == nil {
		r.active = make(map[string]chan struct{})
	}
	entry := r.entries[key]
	if entry != nil && entry.inflight {
		done := entry.done
		r.access.Unlock()
		select {
		case <-ctx.Done():
			return 0, ctx.Err(), false
		case <-r.ctx.Done():
			return 0, r.ctx.Err(), false
		case <-done:
		}
		r.access.Lock()
		result := entry.result
		r.access.Unlock()
		if result.success {
			return result.delay, nil, !result.deferred
		}
		if result.deferred {
			return 0, errSharedNodeProbeDeferred, false
		}
		if force && retryAfterInflight {
			return r.runProbeModeInternal(ctx, endpointKey, key, timeout, ttl, force, retryAfterInflight, probe)
		}
		// Force bypasses cached cadence, not single-flight. A caller that joined
		// an in-flight probe consumes that fresh result instead of immediately
		// launching a duplicate recovery/manual test for the same endpoint.
		return 0, errSharedNodeProbeFailed, true
	}
	if entry != nil && !force && now.Before(entry.result.nextProbeAt) {
		result := entry.result
		r.access.Unlock()
		if result.success {
			return result.delay, nil, false
		}
		if result.deferred {
			return 0, errSharedNodeProbeDeferred, false
		}
		return 0, errSharedNodeProbeFailed, false
	}
	if endpointKey != "" {
		if done := r.active[endpointKey]; done != nil {
			r.access.Unlock()
			select {
			case <-ctx.Done():
				return 0, ctx.Err(), false
			case <-r.ctx.Done():
				return 0, r.ctx.Err(), false
			case <-done:
			}
			return r.runProbeModeInternal(ctx, endpointKey, key, timeout, ttl, force, retryAfterInflight, probe)
		}
		r.active[endpointKey] = make(chan struct{})
	}
	if len(r.entries) >= nodeProfileRegistryLimit {
		r.pruneLocked(now)
		if len(r.entries) >= nodeProfileRegistryLimit {
			if endpointKey != "" {
				done := r.active[endpointKey]
				delete(r.active, endpointKey)
				close(done)
			}
			r.access.Unlock()
			// Do not bypass the registry when every slot is occupied. An
			// unregistered probe would defeat both endpoint single-flight and the
			// global admission bound precisely during the churn it is meant to
			// contain. The caller can retry on the next scheduled cycle.
			return 0, errSharedNodeProbeDeferred, false
		}
	}
	entry = &nodeProfileEntry{inflight: true, done: make(chan struct{})}
	r.entries[key] = entry
	r.access.Unlock()

	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		r.access.Lock()
		entry.result = nodeProfileResult{completedAt: time.Now(), nextProbeAt: time.Now(), deferred: true}
		entry.inflight = false
		close(entry.done)
		entry.done = nil
		if endpointKey != "" {
			done := r.active[endpointKey]
			delete(r.active, endpointKey)
			close(done)
		}
		r.access.Unlock()
		return 0, errSharedNodeProbeDeferred, false
	case <-r.ctx.Done():
		r.access.Lock()
		entry.result = nodeProfileResult{completedAt: time.Now(), nextProbeAt: time.Now(), deferred: true}
		entry.inflight = false
		close(entry.done)
		entry.done = nil
		if endpointKey != "" {
			done := r.active[endpointKey]
			delete(r.active, endpointKey)
			close(done)
		}
		r.access.Unlock()
		return 0, errSharedNodeProbeDeferred, false
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	delay, err := probe(probeCtx)
	cancel()
	// Release the admission slot immediately — never block peers behind GC.
	<-r.slots
	r.completedProbes.Add(1)
	// Let the runtime GC on its own schedule. Forced STW after probes hurt
	// gateway latency and HA close under multi-smart catalogs.
	completedAt := time.Now()
	r.access.Lock()
	previous := entry.result
	// A caller/registry cancellation is not evidence that the endpoint is
	// unhealthy.  This can race the probe callback's return (for example when
	// a group closes while an HTTP probe is unwinding); caching it as a normal
	// failure would make every other Smart group inherit a false breaker. Keep
	// the previous evidence, mark this run deferred, and make the next caller
	// eligible to retry immediately.
	if ctx.Err() != nil || r.ctx.Err() != nil {
		result := previous
		result.completedAt = completedAt
		result.nextProbeAt = completedAt
		result.deferred = true
		entry.result = result
		entry.inflight = false
		close(entry.done)
		entry.done = nil
		if endpointKey != "" {
			done := r.active[endpointKey]
			delete(r.active, endpointKey)
			close(done)
		}
		r.access.Unlock()
		return 0, errSharedNodeProbeDeferred, false
	}
	var successes, failures uint8
	if err == nil {
		successes = min(previous.successes+1, uint8(3))
	} else {
		failures = min(previous.failures+1, uint8(3))
	}
	result := nodeProfileResult{
		delay: delay, success: err == nil, completedAt: completedAt,
		nextProbeAt: completedAt.Add(nodeProfileCadence(err == nil, successes, failures)),
		successes:   successes, failures: failures,
	}
	entry.result = result
	entry.inflight = false
	close(entry.done)
	entry.done = nil
	if endpointKey != "" {
		done := r.active[endpointKey]
		delete(r.active, endpointKey)
		close(done)
	}
	r.access.Unlock()
	if err != nil {
		return 0, errSharedNodeProbeFailed, true
	}
	return delay, nil, true
}

func (r *nodeProfileRegistry) pruneLocked(now time.Time) {
	for key, entry := range r.entries {
		if !entry.inflight && now.Sub(entry.result.completedAt) > time.Hour {
			delete(r.entries, key)
		}
	}
	for len(r.entries) >= nodeProfileRegistryLimit {
		var oldestKey string
		var oldest time.Time
		for key, entry := range r.entries {
			if entry.inflight {
				continue
			}
			if oldestKey == "" || entry.result.completedAt.Before(oldest) {
				oldestKey = key
				oldest = entry.result.completedAt
			}
		}
		if oldestKey == "" {
			break
		}
		delete(r.entries, oldestKey)
	}
}

func (r *nodeProfileRegistry) close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.cancel()
		r.access.Lock()
		clear(r.entries)
		r.entries = make(map[string]*nodeProfileEntry)
		r.access.Unlock()
	})
}
