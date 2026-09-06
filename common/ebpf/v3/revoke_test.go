package v3

import (
	"net/netip"
	"testing"
	"time"
)

// The shared-IP generalisation guard: a learn-promoted /32 DIRECT must be
// revocable when later DNS evidence marks the same address proxy-routed,
// while snapshot-published bypass rules stay protected from accidental
// removal.
func TestMemoryBackendRevokeMergedStaticDirect(t *testing.T) {
	b := NewMemoryBackend()

	// Snapshot: one permanent bypass prefix, committed as bank 1.
	snapshot := []CompiledPolicy{{
		Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 5}), 32),
		Value: PolicyValue{
			Verdict:    uint8(VerdictDirect),
			Source:     uint8(SourceStatic),
			Confidence: ConfidenceStrong,
			ReasonCode: uint16(ReasonStaticDirect),
		},
	}}
	if err := b.PublishStatic(snapshot); err != nil {
		t.Fatal(err)
	}

	// Learn-promote of a different address (dns_prefill path).
	promoted := netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 32)
	if err := b.MergeStaticDirect(promoted); err != nil {
		t.Fatal(err)
	}
	active := b.Control.ActiveBank & 1
	key, err := PrefixToLPM4(promoted)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Policy4[active][key]; !ok {
		t.Fatal("promoted /32 missing from active bank")
	}

	// Shared-IP conflict: revoke the promoted prefix only.
	if err := b.DeleteMergedStaticDirect(promoted); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Policy4[active][key]; ok {
		t.Fatal("revoked /32 still in active bank")
	}

	// Snapshot-published rule must survive an accidental revoke request.
	if err := b.DeleteMergedStaticDirect(snapshot[0].Prefix); err != nil {
		t.Fatal(err)
	}
	snapshotKey, _ := PrefixToLPM4(snapshot[0].Prefix)
	if _, ok := b.Policy4[active][snapshotKey]; !ok {
		t.Fatal("snapshot-published bypass rule was removed by revoke")
	}

	// A full publish rebuild clears the revocable set for the new bank.
	if err := b.MergeStaticDirect(promoted); err != nil {
		t.Fatal(err)
	}
	if err := b.PublishStatic(nil); err != nil {
		t.Fatal(err)
	}
	if len(b.mergedDirects[b.Control.ActiveBank&1]) != 0 {
		t.Fatal("merged set not cleared after snapshot publish")
	}
	_ = time.Now
}
