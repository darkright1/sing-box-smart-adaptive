package group

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

// groupUDPFailureTTL is deliberately short: a failed UDP ListenPacket is
// passive, node-scoped evidence, not proof that the endpoint is permanently
// dead. It must keep TCP URL-test history intact while preventing an immediate
// retry storm against the same member.
const groupUDPFailureTTL = 30 * time.Second

// groupUDPFailureTracker is a bounded, identity-keyed ledger for passive UDP
// failures. It stores only opaque identity strings and expiry timestamps, so a
// provider refresh cannot retain outbound objects or confuse a reordered list.
type groupUDPFailureTracker struct {
	entries *freelru.Cache[string, int64]
}

func newGroupUDPFailureTracker() *groupUDPFailureTracker {
	entries := common.Must1(freelru.New[string, int64](512, maphash.NewHasher[string]().Hash32, true))
	return &groupUDPFailureTracker{entries: entries}
}

func (t *groupUDPFailureTracker) key(outbound adapter.Outbound) string {
	if outbound == nil {
		return ""
	}
	record := selectedRecordForOutbound(outbound)
	switch {
	case record.DialIdentity != "":
		return "d\x00" + record.DialIdentity
	case record.EndpointIdentity != "":
		return "e\x00" + record.EndpointIdentity
	default:
		return "t\x00" + record.DisplayTag
	}
}

func (t *groupUDPFailureTracker) mark(outbound adapter.Outbound) {
	if t == nil || t.entries == nil {
		return
	}
	if key := t.key(outbound); key != "" {
		t.entries.AddWithLifetime(key, time.Now().UnixNano(), groupUDPFailureTTL)
	}
}

func (t *groupUDPFailureTracker) clear(outbound adapter.Outbound) {
	if t == nil || t.entries == nil {
		return
	}
	if key := t.key(outbound); key != "" {
		t.entries.Remove(key)
	}
}

func (t *groupUDPFailureTracker) active(outbound adapter.Outbound) bool {
	if t == nil || t.entries == nil {
		return false
	}
	key := t.key(outbound)
	return key != "" && t.entries.Contains(key)
}
