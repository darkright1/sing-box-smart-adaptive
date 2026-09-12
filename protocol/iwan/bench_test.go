//go:build with_iwan

package iwan

import "testing"

func BenchmarkBuildData1K(b *testing.B) {
	h := Header{SID: 7, Token: 11}
	payload := make([]byte, 1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = BuildData(h, payload, "bench", "secret", false)
	}
}

func BenchmarkBuildDataEncrypted1K(b *testing.B) {
	h := Header{SID: 7, Token: 11}
	payload := make([]byte, 1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = BuildData(h, payload, "bench", "secret", true)
	}
}
