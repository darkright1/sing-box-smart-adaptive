# iWAN native Rust status

`native/iwan` is the private Rust static-library boundary for the next iWAN
dataplane. It currently provides a C ABI for bounded single-frame and batch
DATA framing with the frozen iWAN header and 8-byte XOR wire transform. The
Rust code retains no caller pointers after an ABI call and returns explicit
negative validation errors.

This is a foundation layer, not yet the production native dataplane. The Go
path remains authoritative until the following are integrated and verified on
Linux: TUN queue ownership, UDP socket I/O, VNET/GSO/GRO conversion, native-L3
route/NAT lifecycle, and Go/Rust wire-vector plus failure-injection tests.

Build only on Linux/PVE:

```sh
make -C native/iwan test
make -C native/iwan build TARGET=x86_64-unknown-linux-gnu
```

The static library is deliberately not linked into default builds. A future
`with_iwan_native` integration must pass the existing Go fallback tests and
must fail closed to the Go path when the Rust artifact or mandatory kernel
capabilities are unavailable.
