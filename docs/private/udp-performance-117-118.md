# UDP performance investigation (VM117/VM118)

## Scope

This is a lab-only comparison of the Linux network path, the currently
running sing-box instance on VM117, and the standalone iWAN flow-test
client/server. VM118 is the tunnel client/iperf sender for the iWAN runs. No
production VM (107/115) was changed.

## Reproduction and evidence

Both guests initially exposed one virtio queue (`rx-0/tx-0`). With 1400-byte
iperf3 datagrams:

| Offered | 117 -> 118 (single queue) |
|---:|---:|
| 100 Mbps | 0.0067% loss |
| 500 Mbps | 0.55% loss |
| 1 Gbps | 4.3% loss |

The host NIC (`ens9`) has two RX queues. We changed only the lab VM network
devices to `queues=2` and rebooted them. Both guests then exposed `rx-0/rx-1`
and `tx-0/tx-1`. With the original guest sysctls (`rmem_max/wmem_max=4 MiB`,
`netdev_max_backlog=1000`), both directions at 1 Gbps completed 10 seconds,
1400-byte datagrams, **0/893,xxx lost (0%)**. A temporary buffer/backlog tuning
experiment on the old single-queue setup reduced loss to 0.09%, confirming that
queue/receive scheduling—not packet encoding—was the limiting resource.

## Protocol smoke matrix (VM117 SOCKS5 UDP -> 1.1.1.1:53)

The test selected one concrete endpoint through the Clash API and issued 20
DNS requests. It measures UDP capability/reliability, not line-rate throughput.

| Protocol | Result | Evidence |
|---|---|---|
| Trojan | 20/20, 0% loss | outbound packet connection succeeded |
| VMess | 20/20, 0% loss | outbound packet connection succeeded |
| VLESS | 0/20 | remote dial refused (`connect: connection refused`) |
| Hysteria2 | 0/20 | remote packet session timed out |
| Shadowsocks/TUIC/WireGuard/iWAN | not present as runnable endpoints in this lab |

The VLESS and Hysteria2 failures were reproduced with two different nodes and
are recorded as endpoint/remote capability failures; they are not evidence of
a sing-box UDP core defect. The sing-box eBPF metrics showed no UDP queue
rejections during the SOCKS5 tests.

## Standalone iWAN flow-test tunnel

This is the original standalone iWAN server/client binary (`iwan-flow-test`),
not a sing-box endpoint build. VM117 ran the server and VM118 ran the client
with the socket dataplane, 128 MiB socket buffers, two socket readers, two RX
workers, and two TUN queues. The test route was a temporary `/32` route over
the client TUN; payloads were limited to 800 bytes because the tunnel MTU is
1400 bytes.

| Offered | Receiver result (10 s) |
|---:|---:|
| 100 Mbps | 0/156,330 lost (0%) |
| 500 Mbps | 23/781,363 lost (0.0029%) |
| 600 Mbps | 2,335/937,959 lost (0.25%) |
| 800 Mbps | 2,328/1,250,525 lost (0.19%) |
| 1 Gbps | 8,246/1,512,993 lost (0.55%), 963 Mbps received |

For comparison, the same standalone tunnel with one TUN queue previously
measured about 0.31% loss at 500 Mbps and about 19% loss at 1 Gbps. Thus the
two-queue change materially improves the tunnel, but it does not yet provide
zero-loss 1 Gbps forwarding. The highest repeatable low-loss point observed
was 500 Mbps; 1 Gbps is close to line rate but still drops packets.

There is no valid sing-box-integrated iWAN throughput number in this report:
the production Linux artifact currently running on VM117 has no `with_iwan`
tag. A private Linux `with_iwan,with_gvisor` build was created in the lab and
did pass the endpoint handshake plus 20/20 UDP DNS requests through a mixed
inbound. A burst test of 100,000 x 800-byte packets offered about 385 Mbps;
the receiver got 20,427 packets (16.3 MB). A paced 20,000-packet run offered
34.2 Mbps and received all 20,000 packets. These are functional/path tests,
not a line-rate claim: the sender is a Python SOCKS generator and its burst
loss is not an apples-to-apples iperf result. A proper integrated maximum
requires a native Linux traffic generator and a documented UDP echo target.
The Rust standalone daemon was not used for throughput because its `tun=none`
mode explicitly disables data forwarding.

## Result and action

The actionable fix is infrastructure: retain virtio multiqueue on lab/test VMs
(and size host receive queues appropriately). Do not “fix” this by adding
unbounded per-session buffers in sing-box; that would trade packet loss for
memory growth. The standalone iWAN result points to remaining TUN/worker
queue pressure at line rate, so GSO/GRO and batching should be profiled before
any code change. Production 107/115 remain unchanged. A valid Linux
`with_iwan` artifact and reachable peer are required before claiming
sing-box-integrated iWAN throughput.
