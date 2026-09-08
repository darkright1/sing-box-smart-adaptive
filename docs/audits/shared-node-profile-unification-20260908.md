# Shared node-profile unification

The group strategies now use one process-scoped node profile registry. The
registry is the single source for probe results and transport-scoped passive
failures; strategy-specific state is limited to policy decisions:

- **Smart** owns site-aware scoring, breaker state, stickiness, and Zig/Go
  policy selection. Its probe and real data-plane observations use the same
  credential-aware `DialIdentity` result key.
- **URLTest** consumes the shared TCP latency profile and UDP/TCP passive
  availability. It no longer owns an independent UDP failure ledger.
- **LoadBalance** consumes the same profile and retains only round-robin,
  hash, and sticky-session mapping. Sticky records resolve by `DialIdentity`,
  never by a slice index or a weaker credential-free path identity.

`EndpointIdentity` is used only for admission serialization, so aliases and
credential variants cannot start duplicate probes while their health evidence
remains isolated. TCP and UDP passive failures have distinct keys. A real
Smart, URLTest, or LoadBalance failure is published to the shared passive
ledger for a short, bounded quarantine; a successful connection clears only
that transport's quarantine.

`common/urltest.HistoryStorage` remains as a compatibility projection for the
dashboard and legacy API. It is not consulted by production group selection
when a profile registry is present. Provider health checks likewise continue
to publish their UI-compatible history because the provider package cannot
depend on group policy code; they are not used as Smart/URLTest/LoadBalance
selection truth.

The registry is retained across zero group references and is closed only when
the process context ends. Probe admission is bounded globally and single-flight
per endpoint. Tests cover process sharing, credential separation, provider
refresh identity, TCP/UDP isolation, passive recovery, and concurrent forced
probe coalescing.
