package group

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

const groupPassiveFailureTTL = 30 * time.Second

// groupProfileIdentity separates the credential-sensitive observation key
// from the credential-free endpoint admission key. Probes for credentials on
// one physical path are serialized, while their health results never merge.
func groupProfileIdentity(outbound adapter.Outbound) (endpointKey, dialKey string) {
	record := selectedRecordForOutbound(outbound)
	endpointKey = record.EndpointIdentity
	if endpointKey == "" {
		endpointKey = record.DialIdentity
	}
	if endpointKey == "" {
		endpointKey = record.DisplayTag
	}
	dialKey = record.DialIdentity
	if dialKey == "" {
		dialKey = endpointKey
	}
	return
}

func groupTCPProfileKeyForIdentity(dialKey, link, network string) string {
	if network == "" {
		network = N.NetworkTCP
	}
	return nodeProfileKey(dialKey, link+"\x00"+network, 0)
}

func groupTCPProfileKey(outbound adapter.Outbound, link string, network ...string) (endpointKey, profileKey string) {
	endpointKey, dialKey := groupProfileIdentity(outbound)
	profileNetwork := N.NetworkTCP
	if len(network) > 0 && network[0] != "" {
		profileNetwork = network[0]
	}
	return endpointKey, groupTCPProfileKeyForIdentity(dialKey, link, profileNetwork)
}

func groupUDPProfileKey(outbound adapter.Outbound) string {
	_, dialKey := groupProfileIdentity(outbound)
	return nodeProfileKey(dialKey, "passive\x00"+N.NetworkUDP, 0)
}

func groupTCPPassiveProfileKey(outbound adapter.Outbound) string {
	_, dialKey := groupProfileIdentity(outbound)
	return nodeProfileKey(dialKey, "passive\x00"+N.NetworkTCP, 0)
}

func groupProfileAlive(registry *nodeProfileRegistry, outbound adapter.Outbound, link string, window time.Duration) bool {
	result, loaded := groupTCPProfileSnapshot(registry, outbound, link)
	if !loaded || !result.success || !groupTCPAvailable(registry, outbound) {
		return false
	}
	return window <= 0 || time.Since(result.completedAt) < window
}

func groupTCPAvailable(registry *nodeProfileRegistry, outbound adapter.Outbound) bool {
	return registry == nil || !registry.passiveFailureActive(groupTCPPassiveProfileKey(outbound))
}

func groupTCPProfileSnapshot(registry *nodeProfileRegistry, outbound adapter.Outbound, link string) (nodeProfileResult, bool) {
	if registry == nil {
		return nodeProfileResult{}, false
	}
	_, key := groupTCPProfileKey(outbound, link)
	return registry.snapshot(key)
}

func groupUDPAvailable(registry *nodeProfileRegistry, outbound adapter.Outbound) bool {
	return registry == nil || !registry.passiveFailureActive(groupUDPProfileKey(outbound))
}
