package group

import (
	"context"
	"regexp"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

// groupProviderSource is the shared provider expansion used by selector and
// url-test groups. Smart and load-balance carry their own historically grown
// variants; this helper gives the simpler groups the same member semantics
// (providers + use_all_providers + include/exclude regex) without touching
// those implementations.
type groupProviderSource struct {
	manager         adapter.ProviderManager
	providers       map[string]adapter.Provider
	providerTags    []string
	useAllProviders bool
	exclude         *regexp.Regexp
	include         *regexp.Regexp
	outboundsCache  map[string][]adapter.Outbound
	access          sync.Mutex
}

func newGroupProviderSource(ctx context.Context, options option.GroupCommonOption) *groupProviderSource {
	return &groupProviderSource{
		manager:         service.FromContext[adapter.ProviderManager](ctx),
		providers:       make(map[string]adapter.Provider),
		providerTags:    options.Providers,
		useAllProviders: options.UseAllProviders,
		exclude:         (*regexp.Regexp)(options.Exclude),
		include:         (*regexp.Regexp)(options.Include),
		outboundsCache:  make(map[string][]adapter.Outbound),
	}
}

// has reports whether the group is provider-backed at all. Without this the
// provider update callback must reject everything.
func (s *groupProviderSource) has() bool {
	return s != nil && (len(s.providerTags) > 0 || s.useAllProviders)
}

// register subscribes to provider updates and resolves the configured tags.
func (s *groupProviderSource) register(callback adapter.ProviderUpdateCallback) error {
	if !s.has() {
		return nil
	}
	if s.manager == nil {
		return E.New("missing outbound provider manager")
	}
	if s.useAllProviders {
		var providerTags []string
		for _, provider := range s.manager.Providers() {
			providerTags = append(providerTags, provider.Tag())
			s.providers[provider.Tag()] = provider
			provider.RegisterCallback(callback)
		}
		s.providerTags = providerTags
	} else {
		for i, tag := range s.providerTags {
			provider, loaded := s.manager.Get(tag)
			if !loaded {
				return E.New("outbound provider ", i, " not found: ", tag)
			}
			s.providers[tag] = provider
			provider.RegisterCallback(callback)
		}
	}
	return nil
}

// memberOutbounds returns the deduplicated provider-contributed members with
// their tags, re-filtering only the provider that reported an update.
func (s *groupProviderSource) memberOutbounds(updatedTag string) (tags []string, outbounds []adapter.Outbound) {
	s.access.Lock()
	defer s.access.Unlock()
	for _, providerTag := range s.providerTags {
		if updatedTag != "" && providerTag != updatedTag && s.outboundsCache[providerTag] != nil {
			cached := s.outboundsCache[providerTag]
			for _, detour := range cached {
				tags = append(tags, detour.Tag())
				outbounds = append(outbounds, detour)
			}
			continue
		}
		provider := s.providers[providerTag]
		if provider == nil {
			continue
		}
		var cache []adapter.Outbound
		for _, detour := range provider.Outbounds() {
			tag := detour.Tag()
			if s.exclude != nil && s.exclude.MatchString(tag) {
				continue
			}
			if s.include != nil && !s.include.MatchString(tag) {
				continue
			}
			tags = append(tags, tag)
			outbounds = append(outbounds, detour)
			cache = append(cache, detour)
		}
		s.outboundsCache[providerTag] = cache
	}
	return tags, outbounds
}

// appendProviderMembers merges provider members into the group's explicit
// tag list and outbound map, preserving explicit entries on conflict.
func appendProviderMembers(explicitTags []string, outbounds map[string]adapter.Outbound, source *groupProviderSource, updatedTag string) []string {
	_, members := source.memberOutbounds(updatedTag)
	tags := explicitTags
	seen := make(map[string]struct{}, len(explicitTags)+len(members))
	for _, tag := range explicitTags {
		seen[tag] = struct{}{}
	}
	for _, member := range members {
		tag := member.Tag()
		if _, exists := seen[tag]; !exists {
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}
		outbounds[tag] = member
	}
	return tags
}
