//go:build with_iwan && linux

package iwan

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// A single reader is the safest default for old kernels and small VMs; on
// Linux with SO_REUSEPORT, one reader per socket lets recvmmsg work on
// multiple cores. The count is an endpoint option rather than a process-wide
// environment setting, so separate endpoints cannot affect one another.
const (
	defaultIWANServerSocketReaders = 1
	maxIWANServerSocketReaders     = 8
)

func configuredIWANServerSocketReaders(requested int) int {
	readers := requested
	if readers == 0 {
		readers = defaultIWANServerSocketReaders
	}
	if readers < 1 {
		return 1
	}
	if readers > maxIWANServerSocketReaders {
		return maxIWANServerSocketReaders
	}
	return readers
}

func listenIWANServerSockets(addr *net.UDPAddr, requested int) ([]*net.UDPConn, error) {
	count := configuredIWANServerSocketReaders(requested)
	if count == 1 {
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return nil, err
		}
		return []*net.UDPConn{conn}, nil
	}
	listen := net.ListenConfig{Control: func(_ string, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			if controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); controlErr != nil {
				return
			}
			controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); err != nil {
			return err
		}
		return controlErr
	}}
	result := make([]*net.UDPConn, 0, count)
	for range count {
		packetConn, err := listen.ListenPacket(context.Background(), "udp", addr.String())
		if err != nil {
			closeIWANServerSockets(result)
			// Reuse-port is an optimization, not a startup requirement.  If
			// the kernel rejects it, keep the proven single-reader path.
			fallback, fallbackErr := net.ListenUDP("udp", addr)
			if fallbackErr != nil {
				return nil, err
			}
			return []*net.UDPConn{fallback}, nil
		}
		conn, ok := packetConn.(*net.UDPConn)
		if !ok {
			_ = packetConn.Close()
			closeIWANServerSockets(result)
			return nil, syscall.EPROTOTYPE
		}
		result = append(result, conn)
	}
	return result, nil
}

func closeIWANServerSockets(conns []*net.UDPConn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}
