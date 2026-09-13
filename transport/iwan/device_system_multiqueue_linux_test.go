//go:build with_iwan && linux

package iwan

import "testing"

func TestSystemPacketFlowHashStablePerFiveTuple(t *testing.T) {
	packet := make([]byte, 40)
	packet[0] = 0x45
	packet[9] = 17 // UDP
	copy(packet[12:16], []byte{192, 0, 2, 10})
	copy(packet[16:20], []byte{198, 51, 100, 20})
	packet[20] = 0x1f
	packet[21] = 0x90 // source port 8080
	packet[22] = 0x00
	packet[23] = 0x35 // destination port 53
	if got, want := systemPacketFlowHash(packet), systemPacketFlowHash(packet); got != want {
		t.Fatalf("hash changed for the same five tuple: %d != %d", got, want)
	}
	other := append([]byte(nil), packet...)
	other[23]++
	if systemPacketFlowHash(packet) == systemPacketFlowHash(other) {
		t.Fatal("different destination port used the same flow hash")
	}
}
