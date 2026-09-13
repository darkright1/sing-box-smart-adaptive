# iWAN native Rust status

`native/iwan` is the private Rust static-library boundary for the next iWAN
dataplane. It provides a C ABI for bounded single-frame and batch DATA framing
with the frozen iWAN header and 8-byte XOR wire transform. The Go Linux DATA
writers now call the batch ABI once per batch when built with
`with_iwan_native`; the normal `with_iwan` build remains a byte-for-byte Go
fallback. The Rust code retains no caller pointers after an ABI call and
returns explicit negative validation errors. It also exposes read-only Linux
capability probes for TUN VNET/multi-queue and UDP GRO/SEGMENT state; probes
never enable or mutate an offload.

The ABI preflights an entire batch before writing any output, accepts
overlapping input/output slabs with memmove semantics, and uses
architecture-correct Linux TUN ioctl values. `make test` also compiles C
static assertions against the header so Rust `repr(C)` and C consumers cannot
drift silently.

The batch framing integration is production-safe as an optional accelerator,
but this is not yet the complete native L3 dataplane. Go remains authoritative
for TUN ownership, UDP socket I/O, routing, and lifecycle. The following still
require a separate Linux implementation and acceptance matrix: VNET/GSO/GRO
conversion, native-L3 route/NAT lifecycle, and full Go/Rust failure-injection
coverage for queue/offload ownership.

Build only on Linux/PVE:

```sh
make -C native/iwan test
make -C native/iwan build TARGET=x86_64-unknown-linux-gnu
# From the repository root, private Linux integration:
make build_iwan_native
```

The static library is deliberately not linked into default/public builds.
`with_iwan_native` requires the artifact at
`native/iwan/target/release/libiwan_native.a`; missing artifacts fail the
private build rather than silently producing a binary that claims native
framing. Runtime DATA paths still fall back to the Go framing for SR,
fragmentation, wrapped transports, or builds without the private tag.
