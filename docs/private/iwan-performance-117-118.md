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
