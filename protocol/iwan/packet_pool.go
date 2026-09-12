//go:build with_iwan

package iwan

import "sync"

// The adapter writes a DATA frame synchronously to a datagram socket.  That
// makes the frame safe to recycle immediately after Write returns.  Keep a
// few size classes instead of one unbounded pool: normal MTU-sized frames are
// reused, while malformed/oversized input cannot make the pool retain large
// allocations indefinitely.
const (
	wirePoolMaxSize = 4096
	wirePoolClasses = 4
)

var wirePools = [wirePoolClasses]sync.Pool{
	{New: func() any { return &wirePacket{data: make([]byte, 1536), class: 0} }},
	{New: func() any { return &wirePacket{data: make([]byte, 2048), class: 1} }},
	{New: func() any { return &wirePacket{data: make([]byte, 3072), class: 2} }},
	{New: func() any { return &wirePacket{data: make([]byte, wirePoolMaxSize), class: 3} }},
}

type wirePacket struct {
	data  []byte
	class int
}

func wirePoolClass(size int) (int, bool) {
	switch {
	case size <= 1536:
		return 0, true
	case size <= 2048:
		return 1, true
	case size <= 3072:
		return 2, true
	case size <= wirePoolMaxSize:
		return 3, true
	default:
		return 0, false
	}
}

func acquireWirePacket(size int) ([]byte, *wirePacket) {
	class, ok := wirePoolClass(size)
	if !ok {
		return make([]byte, size), nil
	}
	packet := wirePools[class].Get().(*wirePacket)
	return packet.data[:size], packet
}

func releaseWirePacket(packet []byte, pooled *wirePacket) {
	if pooled == nil || len(packet) > len(pooled.data) {
		return
	}
	if pooled.class < 0 || pooled.class >= len(wirePools) {
		return
	}
	// Put the full class-sized backing array back.  Clearing is unnecessary:
	// the next build overwrites the complete wire frame before it is written.
	wirePools[pooled.class].Put(pooled)
}
