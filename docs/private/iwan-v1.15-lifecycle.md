# iWAN endpoint lifecycle on sing-box 1.15

The iWAN endpoint now implements `adapter.OnDemandEndpoint`, matching the
lifecycle contract used by WireGuard, OpenVPN, and OpenConnect.

## State contract

- `Start(StartStateStart)` performs the initial authenticated UDP handshake and
  starts the virtual device and reader/echo loops.
- `on_demand: true` applies only to client endpoints. The reference manager may
  call `SetKeepIdleConnections(false)` when the endpoint is unreferenced.
- Suspending closes only the authenticated UDP session. The virtual device,
  addresses, routes, and gVisor stack remain alive, so host routing is not
  repeatedly recreated.
- The first TCP or UDP flow after suspension calls `ensureReady`, waits for the
  previous reader and echo loops to finish, creates a fresh session, and
  performs a bounded handshake before the flow proceeds.
- A normal `Close` is terminal and closes the session, device, and server
  runtime. It cannot be undone by an on-demand resume.

## Safety invariants

The endpoint serializes session replacement, writes, and final close with a
single lifecycle mutex. Reader and echo loops use per-session snapshots and
must finish before a new session is installed. A failed resume leaves the
endpoint not-ready and returns the handshake error; it never exposes a
partially initialized session to the data path.

`on_demand` is intentionally opt-in. Existing iWAN configurations keep the
persistent-session behavior and therefore retain their 1.14 compatibility.
