# URLTest history identity audit

## Finding

Provider members can receive display aliases such as `HK`, `HK #2`, and
`HK #3`. The suffix is recomputed when a provider refresh removes or adds a
duplicate. The old URLTest and LoadBalance history storage keyed observations
only by that display tag, so a surviving member could inherit another member's
latency after a refresh.

## Remediation

`common/urltest.HistoryKey` now separates:

- credential-free `PathIdentity` (shared by equivalent network paths),
- a digest of the probe target (the URL itself is never retained), and
- the network family.

URLTest, LoadBalance, provider checks, Clash API, daemon status, and manual
tests use the identity-aware API. Legacy tag-only entries remain available for
ordinary static outbounds, but are never used as a fallback for identified
provider members. Dashboard/status readers select the newest observation for
the same path and network without crossing endpoint identities.

## Verification

Tests cover provider alias isolation, probe-target isolation, network-family
isolation, and static legacy fallback. Run:

```sh
go test ./common/urltest ./protocol/group ./experimental/clashapi ./daemon ./adapter/provider
```
