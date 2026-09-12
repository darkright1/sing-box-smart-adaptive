# Private iWAN endpoint integration

This branch keeps iWAN private and does not publish the protocol or its
configuration to the public repository. The public build registers `iwan` as
an unsupported endpoint and reports that it requires the private `with_iwan`
build tag.

## Contract

`type: "iwan"` is a single sing-box endpoint type. `mode` selects `client` or
`server`; no child process, external daemon, or second control plane is used.
The endpoint must implement the same lifecycle and `adapter.Endpoint` surface
as WireGuard, including Router-mediated TCP/UDP flows and endpoint-side
health/lifecycle reporting.

## Current private work

- `option.IWANEndpointOptions` defines the shared client/server schema.
- `protocol/iwan` contains the independently maintained wire codec and its
  protocol-vector tests, compiled only with `with_iwan`.
- `include/iwan.go`/`include/iwan_stub.go` provide explicit private-build
  rejection and a safe public-build rejection. The endpoint constructor is
  deliberately fail-closed until the Router-backed transport is complete.

## Remaining production gates

The old iWAN daemon couples its TUN reader and UDP session loop directly to an
OS TUN device. It cannot be called from an endpoint without bypassing
sing-box's Router and flow observation. Before enabling registration, the
private adapter must provide:

1. a bounded iWAN session transport with OPEN/ACK/ECHO/CLOSE ownership;
2. a `sing-tun` stack device for TCP, UDP and ICMP, with packet ownership and
   close semantics matching existing endpoint devices;
3. server-side session admission, address allocation and Router callbacks;
4. cancellation-safe Start/Close and failure classification for Smart;
5. Linux client/server integration tests and a private artifact audit proving
   no iWAN symbols or configuration are present in public builds.

Until those gates pass, the endpoint is intentionally registered as an
unsupported feature in both builds and no production deployment is allowed.
