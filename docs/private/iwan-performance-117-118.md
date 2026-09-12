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
`089ae760` was run on VM117 (server) and VM118 (client). The client used a
SOCKS bridge to an iperf3 target on the server, so these results are
**non-qualifying smoke measurements** under the release gate above (they are
not a direct tunnel-address test and cannot establish line-rate capability).

| Client mode | TCP streams | Offered/result | Retransmits |
| --- | ---: | ---: | ---: |
| `system:false` (gVisor) | 4 | 216.0 Mbit/s sent, 198.9 Mbit/s received | 39 |
| `system:true` (kernel TUN + gVisor fallback) | 4 | 226.6 Mbit/s sent, 203.6 Mbit/s received | 49 |

The same SOCKS bridge at 100 Mbit/s UDP offered 62.9 Mbit/s received with
approximately 7.4% sequence gaps. The Python receiver is not a line-rate
instrument, but the loss is sufficient to reject the current compatibility
path for the 1 Gbit/s zero-loss target. The batch workspace change in
`089ae760` did not materially change this ceiling, confirming that the
dominant cost is the userspace/gVisor L3 path rather than per-call slice
allocation. Native Rust L3 dataplane work and a direct tunnel-address harness
remain required before any production performance claim.
