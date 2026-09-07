# LoadBalance identity and UDP isolation audit

The previous sticky-session implementation stored a member slice index in its
LRU. Provider refreshes replace and reorder that slice, so a still-in-range
index could silently select a different endpoint. Sticky entries now store the
versioned `SelectedRecord` used by the rest of the group code. Each lookup
resolves the record against the current catalog, preferring `DialIdentity` and
falling back to `EndpointIdentity` only when the original credential variant is
gone.

LoadBalance and URLTest also had a transport-isolation violation: a failed UDP
`ListenPacket` deleted the member's TCP URL-test history. UDP failures now use a
bounded, 30-second, identity-keyed passive ledger. A successful UDP open clears
that entry; TCP history is never deleted by a UDP failure. The short cooldown
prevents immediate retry storms without turning one destination's transient
UDP failure into a permanent node quarantine.

Regression coverage verifies sticky identity remapping after member reorder,
UDP-only suppression, and preservation of TCP history. The tracker stores only
opaque identities and timestamps, so provider refreshes cannot retain outbound
objects.
