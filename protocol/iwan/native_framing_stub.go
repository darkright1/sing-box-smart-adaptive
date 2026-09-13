//go:build with_iwan && (!with_iwan_native || !cgo || !linux)

package iwan

// Keep the production-compatible Go framing path available on every build
// where the private Rust artifact is absent. The stub deliberately reports
// that native framing was not selected instead of silently claiming support.
func nativeBuildDataBatch(Header, [16]byte, bool, [][]byte) ([][]byte, []*wirePacket, bool, error) {
	return nil, nil, false, nil
}

func nativeIwanEnabled() bool { return false }

func nativeIwanABIVersion() uint32 { return 0 }
