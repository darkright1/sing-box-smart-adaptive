# Private iWAN performance verification

Test date: 2026-09-12 (Asia/Hong_Kong)

The two VMs were tested directly over their isolated 10.254.40.0/24 link.
The measurements below are the repeatable network baseline. A separate
standalone iWAN flow-test run is recorded below; it is not a sing-box
integrated endpoint result because the running sing-box artifact has no
`with_iwan` tag or iWAN endpoint configuration.

| Direction | Transport | Offered | Result |
| --- | --- | ---: | --- |
| 117 → 118 | TCP, 10 s | — | 8.275 Gbit/s received, 4 sender retransmits |
| 118 → 117 | TCP, 10 s | — | 8.466 Gbit/s received, 0 retransmits |
| 117 → 118 | UDP, 10 s | 100 Mbit/s | 100 Mbit/s, 0% loss, 0.019 ms jitter |
| 117 → 118 | UDP, 10 s | 1 Gbit/s | 965 Mbit/s received, 3.4% loss, 0.018 ms jitter |
| 118 → 117 | UDP, 10 s | 1 Gbit/s | 961 Mbit/s received, 3.9% loss, 0.008 ms jitter |

Both guests report two vCPUs and zero NIC error/drop counters. The 1 Gbit/s
UDP loss is therefore a saturation baseline; the 100 Mbit/s result is
loss-free.

## Standalone iWAN flow-test

The original standalone `iwan-flow-test` server ran on VM117 and client on
VM118 using the socket dataplane, two socket readers, two RX workers, 128 MiB
socket buffers, and two TUN queues. Payloads were 800 bytes (tunnel MTU
1400), over a temporary `/32` route:

| Offered | Receiver result (10 s) |
| ---: | ---: |
| 100 Mbit/s | 0/156,330 lost (0%) |
| 500 Mbit/s | 23/781,363 lost (0.0029%) |
| 600 Mbit/s | 2,335/937,959 lost (0.25%) |
| 800 Mbit/s | 2,328/1,250,525 lost (0.19%) |
| 1 Gbit/s | 8,246/1,512,993 lost (0.55%), 963 Mbit/s received |

The same tunnel with one TUN queue previously lost about 19% at 1 Gbit/s.
Two queues remove the major scheduling bottleneck, but 1 Gbit/s is still not
loss-free. The Rust daemon's `tun=none` mode was not included because it
explicitly disables data forwarding.

The private sing-box build still requires a Linux Go 1.25+ toolchain and a
reachable iWAN peer. A sing-box A/B speed result must use the same private
`with_iwan` artifact and equivalent server/client configuration on both VMs;
it must not be inferred from this standalone flow-test. A lab
`with_iwan,with_gvisor` build did complete the endpoint handshake and 20/20
UDP DNS requests. A Python SOCKS burst (100,000 x 800-byte packets, about
385 Mbit/s offered) delivered 20,427 packets; a paced 34.2 Mbit/s run delivered
all 20,000 packets. This is a functional datapath signal, not a maximum-speed
benchmark, because the generator is not a native line-rate traffic tool.

## Integrated sing-box endpoint smoke benchmark

On 2026-09-13 a Linux `with_iwan,with_gvisor` binary from revision
`e7e6fc46` was run on VM117 (server) and VM118 (client). The client used a
direct tunnel-address route to an iperf3 target bound to the server's shared
native TUN. These are still **non-qualifying smoke measurements** under the
release gate above: the guests have two vCPUs and a single virtio interface,
and the run was not the required five 60-second trials.

| Client mode | TCP streams | Offered/result | Retransmits |
| --- | ---: | ---: | ---: |
| `system:true` (shared kernel TUN) | 1 | 182.8 Mbit/s sent, 181.5 Mbit/s received | 50 |
| `system:true` (shared kernel TUN, reverse) | 1 | 146.3 Mbit/s received | 140 |

At a 1 Gbit/s UDP offer over the direct tunnel address, the receiver measured
353 Mbit/s and 64.4% loss. This is a valid functional-path result, but it
rejects the current Go/native-TUN path for the 1 Gbit/s zero-loss target. The
remaining bottleneck is packet-rate processing and framing in the Go endpoint;
the native Rust dataplane and multiqueue harness described above remain
required before any production performance claim.

## 2026-09-13 native-path optimization pass

The integrated path was then changed to batch decoded packets into one TUN
write, reuse Linux recvmmsg backing slots as headroom-aware views (avoiding a
second payload allocation/copy), release every inbound buffer after device
submission, avoid duplicate DATA header parsing, and raise the bounded native
TUN transmit queue to 10,000 packets. The queue increase is applied only when
a system TUN is created.

On the same two-vCPU guests, post-change smoke results were:

| Offer | Receiver | Loss |
| ---: | ---: | ---: |
| UDP 400 Mbit/s | 385 Mbit/s | 3.8% |
| UDP 1 Gbit/s | 486 Mbit/s | 49% |
| TCP 5 s | 205 Mbit/s | 110 retransmits |

The zero-copy and queue changes reduce the earlier 64% UDP loss, but the
native Go endpoint still does not meet the 1 Gbit/s loss-free gate. These are
lab measurements only; no production VM was changed.

## 2026-09-13 hot-path allocation pass

The server peer table now uses a normalized `netip.AddrPort` key instead of
`UDPAddr.String()`, removing one string allocation and a formatting pass from
every received packet. Shared native-TUN egress uses an immutable,
copy-on-update address snapshot loaded atomically, so packet forwarding no
longer takes the server `RWMutex`. Linux TUN batch writes also reuse their
`[][]byte` and temporary-buffer workspace through a bounded pool. Control-plane
peer create/remove remains serialized and publishes a fresh snapshot only on
membership changes. Unit and race tests pass; a new Linux throughput result is
still required before changing the 1 Gbit/s acceptance status.

The Linux server recvmmsg loop also reuses its peer-batch map from a bounded
workspace pool. This removes one map allocation per receive batch while
retaining release-on-all-paths behavior for decoded TUN buffers.

The Linux IPv4 batch writers now reuse one fixed one-buffer slot per message
instead of allocating `[][]byte{packet}` for each datagram. The slots are
cleared when the workspace returns to the pool, and partial `WriteBatch`
progress still drains before slots are reused.

Socket tuning now requests 16 MiB and falls back through `syscall.Conn` to
`SO_RCVBUF`/`SO_SNDBUF` for wrapped UDP connections. The effective size still
depends on `net.core.rmem_max`/`wmem_max`; the code logs and continues when a
host refuses the hint rather than treating a performance hint as a startup
failure.

The tuning walk now follows bounded `Upstream()` wrappers (connection-manager
and accounting layers) before giving up. This closes the common case where a
wrapped native UDP connection otherwise retained the host default buffer.

With the lab kernel queue limits temporarily raised to 64 MiB, the wrapped
client socket reported `rb33554432` (the expected kernel-doubled 16 MiB
request). A repeat measured 389 Mbit/s at a 400 Mbit/s offer with 2.8% loss,
and 454 Mbit/s at a 1 Gbit/s offer with 54% loss. The client TUN still counted
457,810 TX drops and the server UDP counters rose by 52,296 receive-buffer
errors during the run. The larger socket queue therefore removes a wrapper
configuration gap but does not close the packet-rate/TUN-reader bottleneck;
the 1 Gbit/s loss-free gate remains unmet. The temporary sysctl changes and
lab processes were stopped and the original 4 MiB kernel limits restored.

## 2026-09-13 client dispatch hot-path pass

The client-side native path now retains the IPv4 batch-socket wrapper for the
authenticated UDP session instead of constructing one for every TUN batch.
The Linux multi-queue dispatcher also uses a fixed stack batch and pre-sized
per-queue write buckets; its flow hash is an inline FNV-1a implementation with
no `hash.Hash` or temporary one-byte slices. These changes reduce allocator and
lock pressure without changing packet ordering, queue sharding, MTU handling,
or the bounded backpressure behavior.

The change was validated on Linux with `go test -race` and `go vet` for the
iWAN protocol and device packages, plus a full tagged build. A fresh line-rate
throughput run for this exact revision is still required; the last verified
integrated smoke result remains 389 Mbit/s at a 400 Mbit/s offer (2.8% loss)
and 454 Mbit/s at a 1 Gbit/s offer (54% loss).
