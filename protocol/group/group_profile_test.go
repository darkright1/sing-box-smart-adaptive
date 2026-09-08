package group

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

type sharedProfileTestOutbound struct {
	adapter.Outbound
	tag      string
	endpoint string
	dial     string
}

func (o *sharedProfileTestOutbound) Tag() string              { return o.tag }
func (o *sharedProfileTestOutbound) Network() []string        { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o *sharedProfileTestOutbound) EndpointIdentity() string { return o.endpoint }
func (o *sharedProfileTestOutbound) DialIdentity() string     { return o.dial }

func seedSharedTCPProfile(t *testing.T, registry *nodeProfileRegistry, outbound adapter.Outbound, link string, delay uint16) {
	t.Helper()
	endpointKey, profileKey := groupTCPProfileKey(outbound, link)
	if _, err, _ := registry.runProbeMode(context.Background(), endpointKey, profileKey, time.Second, time.Minute, true, func(context.Context) (uint16, error) {
		return delay, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGroupProfileRegistryIsSharedForProcessLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	first, releaseFirst := acquireGroupProfileRegistry(ctx)
	second, releaseSecond := acquireGroupProfileRegistry(ctx)
	if first != second {
		t.Fatal("groups in one process received different profile registries")
	}
	if existing := existingGroupProfileRegistry(); existing != first {
		t.Fatal("API lookup did not find the active process profile registry")
	}
	releaseFirst()
	releaseSecond()
	third, releaseThird := acquireGroupProfileRegistry(ctx)
	if third != first {
		t.Fatal("zero group references discarded process-lifetime profiles")
	}
	releaseThird()
	cancel()
}

func TestSmartURLTestAndLoadBalanceShareOneTCPProfile(t *testing.T) {
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	link := "https://www.gstatic.com/generate_204"
	fast := &sharedProfileTestOutbound{tag: "fast", endpoint: "path-a", dial: "dial-a"}
	slow := &sharedProfileTestOutbound{tag: "slow", endpoint: "path-b", dial: "dial-b"}
	seedSharedTCPProfile(t, registry, fast, link, 20)
	seedSharedTCPProfile(t, registry, slow, link, 80)

	smart := &Smart{probeURL: link}
	metadata := smart.buildCandidateMetadataWithDialIdentity(fast.Tag(), fast.EndpointIdentity(), fast.DialIdentity())
	_, profileKey := groupTCPProfileKey(fast, link)
	if metadata.probeKey != profileKey {
		t.Fatalf("Smart profile key %q differs from group profile key %q", metadata.probeKey, profileKey)
	}

	urlGroup := &URLTestGroup{
		outbounds:       []adapter.Outbound{slow, fast},
		link:            link,
		tolerance:       10,
		profileRegistry: registry,
	}
	if selected, tested := urlGroup.Select(N.NetworkTCP); selected != fast || !tested {
		t.Fatalf("URLTest selected=%v tested=%v, want shared fast profile", selected, tested)
	}

	balanceGroup := &LoadBalanceGroup{
		outbounds:       []adapter.Outbound{fast, slow},
		snapshotCache:   []adapter.Outbound{fast, slow},
		link:            link,
		interval:        time.Minute,
		profileRegistry: registry,
	}
	if !balanceGroup.memberAvailable(fast, &adapter.InboundContext{Network: N.NetworkTCP}) || !balanceGroup.memberAvailable(slow, &adapter.InboundContext{Network: N.NetworkTCP}) {
		t.Fatal("LoadBalance did not consume the shared TCP profiles")
	}
}

func TestURLTestAndLoadBalanceShareUDPFailureEvidence(t *testing.T) {
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	member := &sharedProfileTestOutbound{tag: "member", endpoint: "path", dial: "dial"}
	registry.recordPassive(groupUDPProfileKey(member), false, 0, groupPassiveFailureTTL)
	if groupUDPAvailable(registry, member) {
		t.Fatal("shared UDP failure remained available")
	}
	registry.recordPassive(groupUDPProfileKey(member), true, 0, 0)
	if !groupUDPAvailable(registry, member) {
		t.Fatal("shared UDP recovery did not clear the failure")
	}
}

func TestURLTestAndLoadBalanceShareTCPPassiveFailure(t *testing.T) {
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	link := "https://www.gstatic.com/generate_204"
	member := &sharedProfileTestOutbound{tag: "member", endpoint: "path", dial: "dial"}
	seedSharedTCPProfile(t, registry, member, link, 20)
	registry.recordPassive(groupTCPPassiveProfileKey(member), false, 0, groupPassiveFailureTTL)
	if groupProfileAlive(registry, member, link, time.Minute) {
		t.Fatal("passive TCP failure did not suppress the shared active profile")
	}
	registry.recordPassive(groupTCPPassiveProfileKey(member), true, 0, 0)
	if !groupProfileAlive(registry, member, link, time.Minute) {
		t.Fatal("passive TCP recovery did not restore the shared active profile")
	}
}

func TestNodeProfileForceProbeJoinsInflightResult(t *testing.T) {
	registry := newNodeProfileRegistry(context.Background())
	defer registry.close()
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	probe := func(context.Context) (uint16, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return 17, nil
	}
	type result struct {
		delay uint16
		err   error
	}
	results := make(chan result, 2)
	var wait sync.WaitGroup
	run := func() {
		defer wait.Done()
		delay, err, _ := registry.runProbeMode(context.Background(), "path", "dial", time.Second, time.Minute, true, probe)
		results <- result{delay: delay, err: err}
	}
	wait.Add(1)
	go run()
	<-started
	wait.Add(1)
	go run()
	// The first probe is deliberately blocked, so the second caller can only
	// join its single-flight entry; it cannot observe a completed cache entry.
	time.Sleep(10 * time.Millisecond)
	close(release)
	wait.Wait()
	close(results)
	for result := range results {
		if result.err != nil || result.delay != 17 {
			t.Fatalf("joined force probe = (%d, %v), want (17, nil)", result.delay, result.err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("force probes executed %d times, want one shared probe", got)
	}
}

func TestNodeProfilesSeparateCredentialsOnOnePath(t *testing.T) {
	first := &sharedProfileTestOutbound{tag: "node", endpoint: "path", dial: "credential-a"}
	second := &sharedProfileTestOutbound{tag: "node #2", endpoint: "path", dial: "credential-b"}
	firstEndpoint, firstKey := groupTCPProfileKey(first, "https://probe")
	secondEndpoint, secondKey := groupTCPProfileKey(second, "https://probe")
	if firstEndpoint != secondEndpoint {
		t.Fatal("same path did not share probe admission identity")
	}
	if firstKey == secondKey {
		t.Fatal("different credentials shared health result identity")
	}
}
