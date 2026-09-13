//go:build with_iwan && with_iwan_native && cgo && linux

package iwan

/*
#cgo CFLAGS: -I${SRCDIR}/../../native/iwan/include
#cgo LDFLAGS: -L${SRCDIR}/../../native/iwan/target/release -liwan_native -ldl -lm -lpthread
#include "iwan_native.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

// nativeBuildDataBatch is deliberately the only cgo entry point on the DATA
// framing path. The descriptor array and all frame storage are allocated by
// the Go pools; Rust does not retain any of the pointers after returning.
// Keeping the call batch-scoped avoids reintroducing a cgo transition per
// packet, which would erase the benefit of the Linux sendmmsg path.
func nativeBuildDataBatch(h Header, key [16]byte, encrypted bool, payloads [][]byte) (frames [][]byte, pools []*wirePacket, used bool, err error) {
	if len(payloads) == 0 {
		return nil, nil, true, nil
	}
	descSize := C.size_t(unsafe.Sizeof(C.iwan_native_packet_desc{}))
	descMemory := C.malloc(C.size_t(len(payloads)) * descSize)
	if descMemory == nil {
		return nil, nil, true, errors.New("iWAN native descriptor allocation failed")
	}
	defer C.free(descMemory)
	desc := unsafe.Slice((*C.iwan_native_packet_desc)(descMemory), len(payloads))
	frames = make([][]byte, len(payloads))
	pools = make([]*wirePacket, len(payloads))
	h.Type = PTData
	h.Encrypt = boolByte(encrypted)
	if encrypted {
		h.Type = PTDataEnc
	}
	for i, payload := range payloads {
		frame, pool := acquireWirePacket(HeaderLen + len(payload))
		frames[i], pools[i] = frame, pool
		desc[i].header.kind = C.uint8_t(h.Type)
		desc[i].header.encrypt = C.uint8_t(h.Encrypt)
		desc[i].header.sid_be = C.uint16_t(h.SID)
		desc[i].header.token_be = C.uint32_t(h.Token)
		if len(payload) != 0 {
			desc[i].payload = (*C.uint8_t)(unsafe.Pointer(&payload[0]))
		}
		desc[i].payload_len = C.size_t(len(payload))
		if encrypted {
			desc[i].key = (*C.uint8_t)(unsafe.Pointer(&key[0]))
		}
		desc[i].output = (*C.uint8_t)(unsafe.Pointer(&frame[0]))
		desc[i].output_cap = C.size_t(len(frame))
	}
	result := C.iwan_native_build_batch((*C.iwan_native_packet_desc)(descMemory), C.size_t(len(payloads)))
	runtime.KeepAlive(payloads)
	runtime.KeepAlive(frames)
	runtime.KeepAlive(key)
	if result < 0 {
		for i := range frames {
			releaseWirePacket(frames[i], pools[i])
		}
		return nil, nil, true, errors.New("iWAN native DATA batch rejected")
	}
	return frames, pools, true, nil
}

func nativeIwanEnabled() bool { return true }

func nativeIwanABIVersion() uint32 { return uint32(C.iwan_native_abi_version()) }
