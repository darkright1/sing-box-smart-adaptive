//go:build with_iwan && !linux

package iwan

import (
	"net"

	"github.com/sagernet/sing/common/buf"
	"golang.org/x/net/ipv6"
)

func (e *Endpoint) writeOutboundBatch6(_ net.Conn, _ *ipv6.PacketConn, _ *Session, _ uint32, _ []*buf.Buffer) (bool, error) {
	return false, nil
}

func (e *Endpoint) readLoopBatch6() bool { return false }
