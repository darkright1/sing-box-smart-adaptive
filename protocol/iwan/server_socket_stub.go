//go:build with_iwan && !linux

package iwan

import "net"

func listenIWANServerSockets(addr *net.UDPAddr, _ int) ([]*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return []*net.UDPConn{conn}, nil
}

func closeIWANServerSockets(conns []*net.UDPConn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}
