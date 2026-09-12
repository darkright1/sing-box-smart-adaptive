//go:build with_iwan && !linux

package iwan

import "github.com/sagernet/sing/common/buf"

func (e *Endpoint) readLoopBatch() bool { return false }

func (e *Endpoint) writeOutboundBatch(_ []*buf.Buffer) (bool, error) { return false, nil }
