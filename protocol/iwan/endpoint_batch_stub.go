//go:build with_iwan && !linux

package iwan

func (e *Endpoint) readLoopBatch() bool { return false }
