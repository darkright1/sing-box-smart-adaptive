package group

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

// historyKeyForOutbound resolves a group to its current leaf before deriving
// the URL-test identity. The display tag is returned only for compatibility
// with static/legacy cache entries; identified provider members never fall
// back to a reused duplicate alias.
func historyKeyForOutbound(manager adapter.OutboundManager, detour adapter.Outbound, link, network string) (urltest.HistoryKey, string) {
	realTag := detour.Tag()
	if manager != nil {
		realTag = RealTag(manager, detour)
		if leaf, loaded := manager.Outbound(realTag); loaded {
			detour = leaf
		}
	}
	return urltest.KeyForOutbound(detour, link, network), realTag
}
