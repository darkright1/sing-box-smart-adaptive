//go:build with_iwan && with_iwan_native && cgo && linux

package iwan

import "testing"

func TestNativeABIVersion(t *testing.T) {
	if got := nativeIwanABIVersion(); got != 1 {
		t.Fatalf("unexpected native iWAN ABI version: %d", got)
	}
}

func TestNativeBatchWireParity(t *testing.T) {
	header := Header{SID: 0x1203, Token: 0x04050607}
	key := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	payloads := [][]byte{nil, []byte("short"), []byte("a longer iWAN payload"), []byte("four")}
	frames, pools, used, err := nativeBuildDataBatch(header, key, true, payloads)
	if err != nil {
		t.Fatal(err)
	}
	if !used || len(frames) != len(payloads) {
		t.Fatalf("native batch not selected: used=%v frames=%d", used, len(frames))
	}
	defer func() {
		for i := range frames {
			releaseWirePacket(frames[i], pools[i])
		}
	}()
	for i, payload := range payloads {
		expected := buildDataWithKey(header, payload, key, true)
		if string(frames[i]) != string(expected) {
			t.Fatalf("frame %d differs from Go wire vector: got=%x want=%x", i, frames[i], expected)
		}
	}
}
