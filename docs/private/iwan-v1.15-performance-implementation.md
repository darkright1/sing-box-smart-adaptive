# iWAN 1.15 Native Dataplane Implementation Plan

## Objective and release boundary

iWAN remains a private `endpoint` compiled into sing-box, at the same lifecycle
level as WireGuard. It must not depend on an external daemon and no private
protocol source, symbols, test vectors, or artifacts may enter the public
repository.

The production target is the Linux native L3 path. The current `system: false`
gVisor/Router path remains a compatibility mode for per-flow sing-box routing,
but it is not eligible for the line-rate performance claim.

The release gate is deliberately strict:

- TCP receive throughput must be at least 90% of the same-host direct baseline
  with four streams, and at least 85% with one stream.
- UDP must deliver at least 1.0 Gbit/s of inner payload with zero lost,
  duplicated, or corrupted datagrams. A 1.2 Gbit/s run is the preferred gate
  when the direct baseline can sustain it losslessly.
- A result is accepted only when the direct baseline for that exact VM, queue,
  payload, duration, and direction is itself clean.

For the observed 8.9 Gbit/s TCP baseline, the four-stream gate is 8.01 Gbit/s.
This is a release criterion, not a prediction that the current implementation
already reaches it.

## Current bottlenecks to remove

The current integrated endpoint has several packet-rate ceilings:

1. `writeOutbound` and `writePeer` call `UDPConn.Write`/`WriteToUDP` once per
   packet under shared locks; receive batching therefore loses most of its
   benefit on egress.
2. MTU fragmentation still creates temporary payload copies and slices unless
   it uses the pooled two-piece builder; this is a high-PPS allocation spike
   on reduced-MTU links.
3. Client and server data packets are copied into new `buf.Buffer` objects,
   followed by another gVisor buffer copy. Packet ownership is not carried
   across the whole receive-decode-forward-write transaction.
4. One UDP socket, one receive loop, and global/session write mutexes serialize
   independent queues and peers.
5. Control traffic and bulk DATA share the same writer lock and socket path.
6. The gVisor server path converts every inner flow into a sing-box connection.
   This is necessary for Router policy, but it is the wrong path for a native
   L3 VPN throughput claim.
6. The endpoint has no complete Linux UDP GSO/GRO, TUN VNET header, multiqueue,
   persistent syscall workspace, or per-layer drop telemetry contract.

## Target architecture

### Control plane

Go remains the single owner of endpoint configuration, `Start`/`Close`,
on-demand state, Router registration, logging, users, and observable failures.
It passes immutable session snapshots to the dataplane. OPEN/ACK/ECHO/CLOSE,
authentication, rekey, NAT rebinding, and peer expiry run on a dedicated
bounded control lane and cannot acquire DATA-path locks.

### Private native dataplane

A private Rust static library is linked into the sing-box binary behind
`with_iwan_native`. It is an internal implementation detail, not a child
process or plugin. The Go/Rust ABI operates on batches only; a cgo call per
packet is forbidden.

The Rust side owns:

- Linux TUN multiqueue file descriptors and outer UDP sockets;
- persistent `recvmmsg`/`sendmmsg` descriptor arrays;
- `UDP_GRO` receive expansion and `UDP_SEGMENT` transmit coalescing;
- `IFF_VNET_HDR`, `TUNSETOFFLOAD`, checksum, TCP/UDP GSO and GRO conversion;
- fixed-size packet slabs with protocol headroom and explicit ownership tags;
- per-queue workers and SPSC handoff rings;
- lock-free read-mostly session lookup using immutable generations;
- per-stage counters for receive, validate, decrypt, route, enqueue, syscall,
  TUN, overflow, stale generation, and shutdown drops.

The native server uses kernel L3 forwarding for the high-performance mode.
Packets are not converted to gVisor TCP/UDP streams. nftables/NAT and routes
are installed through a scoped lifecycle transaction and removed on close.
The existing Router mode remains selectable when sing-box policy routing is
required on the server. Native and Router modes use the same wire protocol,
authentication, peer lifecycle, and configuration model; choosing the fast
path must not create a second iWAN protocol implementation.

Capability selection is automatic. Startup probes TUN multiqueue, VNET header,
UDP GSO/GRO, `recvmmsg`/`sendmmsg`, route/NAT permissions, and usable queue
count. `auto` chooses native only when its complete requirement set passes;
otherwise it records the rejected capability and uses Router mode. A partially
enabled native path is forbidden.

The user-facing configuration adds only `routing_mode: auto|native|router`;
`auto` is the default. Queue count, batch size, GSO size, and ring capacity are
implementation details selected from capabilities and bounded defaults rather
than permanent tuning knobs. Explicit `native` fails startup if its mandatory
capabilities are unavailable; `auto` falls back. Runtime status exposes the
selected mode, queue count, enabled offloads, and every fallback reason.

The wire format is frozen. Performance work may change storage, batching, and
scheduling, but not packet layout, authentication, encryption, session identity
or official-client behavior. The native library must pass the same wire-vector
suite as the Router implementation before any throughput result is considered.

### Queue and ordering model

Each TUN queue has one owner worker. A flow hash selects a stable queue so a
single TCP flow is never reordered. Multiple outer sockets may be used only
with a protocol-defined flow-to-lane mapping; packets from one flow do not
round-robin across lanes. `SO_REUSEPORT` alone is not treated as multiqueue
because one UDP five-tuple normally hashes to one receive queue.

All queues are bounded. Saturation produces a named counter and backpressure;
it may not create unbounded goroutines, Rust tasks, or retained buffers.

## Implementation sequence

### Phase 0 — trustworthy harness

Create a Linux-only private harness using VM117/118 plus an isolated target
namespace behind the server. It must use the tunnel addresses directly, not a
SOCKS bridge, loopback hairpin, or an iperf target on the iWAN server itself.
Record immutable manifests: binary SHA-256, git revision, build tags, kernel,
vCPU, virtio queue count, MTU, offloads, sysctls, IRQ affinity, and commands.

Every test runs in both directions. Baseline and tunnel runs alternate to
detect host contention. Five 60-second trials follow a 10-second warm-up; a
10-minute sustained run and a 24-hour functional soak close the release gate.

### Phase 1 — batch I/O and ownership

Replace per-packet UDP writes with persistent `sendmmsg` batches. Carry packet
storage from TUN/UDP receive through protocol processing to the final syscall,
returning it to the original slab only after completion. Separate control and
DATA writers. The current Go implementation now uses persistent IPv4 batch
workspaces, pooled DATA frames, and pooled two-piece IPFRAG frames; it also
reuses the cached packet socket wrapper. Add partial-send retry and
failure-injection tests for every ownership transition before moving the same
ownership contract into a native library.

### Phase 2 — GSO/GRO and multiqueue

Enable VNET headers and TUN offloads only after capability probing. Implement
ordinary, TCP GSO, UDP GSO, GRO-expanded, checksum-partial, fragmented, and
fallback paths. The fallback must be functionally identical and automatically
selected when the kernel rejects an offload. Bring up one worker per TUN queue
and verify stable flow ordering under concurrent traffic.

### Phase 3 — native L3 server path

Add `routing_mode: native` for kernel forwarding and keep
`routing_mode: router` for the existing sing-box Router path. Route/NAT setup
is transactional: preflight, apply inactive state, activate, then retire the
old generation. Any incomplete apply disables native forwarding and leaves the
endpoint in Router/fail-closed mode.

### Phase 4 — profiling and removal

Collect CPU profiles, allocation profiles, syscall rates, scheduler latency,
softnet drops, UDP socket errors, and per-stage iWAN counters at 0.1, 0.5, 1.0,
1.2, 2.0 and 5.0 Gbit/s. Remove locks, copies, or wakeups only when the same
profile and loss counters prove the bottleneck. Experimental branches that do
not improve the acceptance matrix are deleted rather than retained as knobs.

## Detailed acceptance matrix

| Area | Mandatory acceptance |
| --- | --- |
| TCP throughput | 1 and 4 streams, both directions, 5 x 60 s; median and worst accepted trial meet 85%/90% of the adjacent direct baseline |
| TCP reliability | No connection reset, RTO burst, stall interval, or unexplained zero-throughput second; retransmits per GiB no more than direct baseline + 5% |
| UDP throughput | 1200-byte and 1400-byte inner datagrams at 1.0 Gbit/s for 5 x 60 s in both directions with 0 loss, 0 duplicate, 0 corruption and 0 reorder outside the protocol contract |
| UDP headroom | 1.2 Gbit/s clean when direct baseline is clean; otherwise document the hardware ceiling and do not claim above-baseline capability |
| Packet sizes | 64, 256, 800, 1200, 1400 bytes; IPv4 and IPv6; mixed-size concurrent traffic |
| Offloads | GSO/GRO on and forced-off fallback both pass; kernel capability rejection is automatic and logged once |
| Correctness | official-client wire vectors, plain/encrypted DATA, SR, fragmentation, MTU/DF, NAT rebinding, reconnect, same-account multi-session and stale CLOSE isolation |
| Lifecycle | start, reload, on-demand suspend/resume and close under traffic; no use-after-close, leaked FD, stale route/NAT rule or dead queue |
| Memory | bounded slabs/rings; RSS reaches a plateau; 30-minute constant load shows no monotonic heap/RSS/FD growth |
| CPU | no global mutex hotspot; queue workers scale with available queues; profiles and per-core utilization are included with every throughput result |
| Observability | `rx/tx_packets`, bytes, batch histogram, GRO/GSO, queue depth/high-water, drops by reason, auth/protocol failures, socket/TUN errors and active mode are exported |
| Compatibility | `system:false` Router mode and builds without the private tag remain functional; public binaries contain no iWAN implementation or protocol strings |

UDP has no retransmission mechanism. Its acceptance language is therefore
zero packet loss/duplication/corruption/reordering. TCP retransmission is
measured separately and normalized against the adjacent direct baseline.

## Test invalidation rules

A result is discarded if any of the following occurs: test traffic reaches the
target outside the tunnel; the test target is a loopback/self-hairpin on the
iWAN server; direct baseline is lossy; another iperf listener shares the port;
queue/offload/sysctl state changes between baseline and tunnel; socket/TUN/NIC
counters are missing; warm-up is reported as the result; or only the sender
number is available.

No average may hide a failed trial. Any zero-throughput interval, queue drop,
or unexplained reconnect fails the run even if the final mean exceeds the
throughput gate.

## Deployment gate

All work stays on VM117/118 until the full matrix passes. The private build is
then deployed to one idle canary for 24 hours with automatic rollback on
endpoint crash, route leak, loss counter increase, or lifecycle failure. VM107
and VM115 are not eligible until the native mode, functional matrix, 10-minute
stress run, 24-hour soak, and rollback drill all pass.
