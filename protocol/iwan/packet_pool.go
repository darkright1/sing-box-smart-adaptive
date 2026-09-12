//go:build with_iwan

package iwan

// The sing-box adapter owns its packet lifetime, so the protocol package
// deliberately exposes allocation-neutral helpers.  A future Linux build can
// replace these with a bounded pool without changing the wire API.
func acquireWirePacket(size int) ([]byte, bool) { return make([]byte, size), false }

func releaseWirePacket(_ []byte, _ bool) {}
