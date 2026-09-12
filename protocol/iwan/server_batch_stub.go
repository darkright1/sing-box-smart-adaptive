//go:build with_iwan && !linux

package iwan

// Non-Linux platforms keep the portable ReadFromUDP loop. Linux has a
// recvmmsg-backed implementation in server_batch_linux.go.
func (s *serverRuntime) readLoopBatch() bool { return false }
