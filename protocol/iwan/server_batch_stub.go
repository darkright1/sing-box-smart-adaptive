//go:build with_iwan && !linux

package iwan

import "github.com/sagernet/sing/common/buf"

// Non-Linux platforms keep the portable ReadFromUDP loop. Linux has a
// recvmmsg-backed implementation in server_batch_linux.go.
func (s *serverRuntime) readLoopBatch() bool { return false }

func (s *serverRuntime) writePeerBatch(_ *serverPeer, _ []*buf.Buffer) (bool, error) {
	return false, nil
}
