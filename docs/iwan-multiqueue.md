# iWAN system-mode multi-queue TUN

System-mode iWAN now uses one Linux TUN interface with multiple queue file
descriptors when the host exposes more than one usable processor and the
kernel accepts `IFF_MULTI_QUEUE`. No second TUN device is created. A failed
probe (old kernel, missing `/dev/net/tun`, unsupported flags, or an
incompatible namespace) falls back to the existing single-queue sing-tun
path before the service is started.

Each queue keeps sing-tun's native GSO and batch read/write implementation.
Readers are independent. Packets are assigned to bounded workers using an
IPv4/IPv6 five-tuple hash: packets in one flow share an ordering shard while
unrelated UDP flows can be encrypted and submitted concurrently. The worker
channels are bounded (256 packets per shard); overload drops only at the
dispatcher boundary instead of growing memory without limit.

The wrapper deliberately enables multi-queue only for iWAN's current system
mode (`AutoRoute=false`, host namespace). Full sing-tun route/rule and network
namespace ownership remains the fallback path, so callers using those options
retain the upstream lifecycle semantics. GSO probing and descriptor close are
delegated to sing-tun for every queue; a queue read failure closes the whole
set to avoid stranded readers.

Queue selection is automatic from `GOMAXPROCS`, capped at four. Operators may
set `SINGBOX_IWAN_TUN_QUEUES` to a positive value for a lab override; kernel
capability detection still wins and silently selects one queue when needed.

Validation requirements:

```sh
go test -race -tags with_iwan ./protocol/iwan ./transport/iwan
```

The feature is Linux-only and must be validated on the target kernel before a
production rollout. The log line includes the selected queue count.
