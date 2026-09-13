//go:build with_iwan && !linux

package iwan

import (
	"net"

	"github.com/sagernet/sing/common/buf"
	"golang.org/x/net/ipv4"
)

func (e *Endpoint) readLoopBatch() bool { return false }

func (e *Endpoint) writeOutboundBatch(_ net.Conn, _ *ipv4.PacketConn, _ *Session, _ uint32, _ []*buf.Buffer) (bool, error) {
	return false, nil
}
