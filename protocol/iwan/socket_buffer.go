//go:build with_iwan

package iwan

import "net"

// Keep enough kernel queue for a short scheduler pause without reserving the
// very large buffers used by the standalone benchmark.  This is a per-session
// bound (not a global allocation) and is only a hint to the operating system.
const iwanSocketBufferSize = 8 << 20

type packetSocketBufferSetter interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

func tunePacketSocket(conn net.Conn) error {
	setter, ok := conn.(packetSocketBufferSetter)
	if !ok {
		return nil
	}
	if err := setter.SetReadBuffer(iwanSocketBufferSize); err != nil {
		return err
	}
	return setter.SetWriteBuffer(iwanSocketBufferSize)
}
