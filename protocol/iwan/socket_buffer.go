//go:build with_iwan

package iwan

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Keep enough kernel queue for a short scheduler pause without reserving the
// very large buffers used by the standalone benchmark. This is a per-UDP
// socket bound (not a global allocation) and is only a hint to the OS.
const iwanSocketBufferSize = 16 << 20

type packetSocketBufferSetter interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

func tunePacketSocket(conn net.Conn) error {
	var firstErr error
	for depth := 0; conn != nil && depth < 8; depth++ {
		supported, err := tunePacketSocketOne(conn)
		if supported {
			if err == nil {
				return nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		upstreamer, ok := conn.(interface{ Upstream() any })
		if !ok {
			break
		}
		upstream, ok := upstreamer.Upstream().(net.Conn)
		if !ok {
			break
		}
		conn = upstream
	}
	return firstErr
}

func tunePacketSocketOne(conn net.Conn) (bool, error) {
	var firstErr error
	supported := false
	if setter, ok := conn.(packetSocketBufferSetter); ok {
		supported = true
		if err := setter.SetReadBuffer(iwanSocketBufferSize); err != nil {
			firstErr = err
		}
		if err := setter.SetWriteBuffer(iwanSocketBufferSize); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	// Dialer wrappers do not always expose net.UDPConn's buffer methods, but
	// most still preserve syscall.Conn. Tune the underlying descriptor as a
	// compatibility fallback so wrapped native UDP sockets do not silently
	// retain the 212 KiB default queue.
	if syscallConn, ok := conn.(syscall.Conn); ok {
		supported = true
		raw, err := syscallConn.SyscallConn()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			var socketErr error
			controlErr := raw.Control(func(fd uintptr) {
				if socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, iwanSocketBufferSize); socketErr != nil {
					return
				}
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, iwanSocketBufferSize)
			})
			if controlErr != nil && firstErr == nil {
				firstErr = controlErr
			} else if socketErr != nil && firstErr == nil {
				firstErr = socketErr
			}
		}
	}
	return supported, firstErr
}
