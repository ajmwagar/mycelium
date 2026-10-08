# Optional Iroh peer sync

Iroh can carry Mycelium's existing signed gossip between enrolled peers. It
does not carry Unibus traffic, grant access, enroll a new peer, or apply LAN
routes or WireGuard tunnels. TCP/mTLS remains available independently.

Build the optional CLI/daemon runtime:

```sh
cargo install --path crates/mycelium-cli --features iroh-sync --locked
```

On each already-enrolled peer, retain the existing `MYCELIUM_PEER_CA`,
`MYCELIUM_PEER_CERT`, and `MYCELIUM_PEER_KEY` settings. Set
`MYCELIUM_IROH_SERVER_NAME` in its daemon environment to a name/IP present
in **that peer's certificate SAN**, then:

```sh
mycelium sync enable --write
mycelium daemon stop
mycelium daemon start
mycelium sync export --qr
```

For a system-managed daemon, restart its existing service rather than starting
a second daemon. Export may briefly fail until local address discovery completes.
The QR contains public connection hints and the TLS name; no private key,
authority grant, SSH permission, or enrollment secret is included.

Save the exported JSON (or scanned QR content) on the other enrolled peer:

```sh
mycelium sync join rendezvous.json --write
mycelium daemon stop
mycelium daemon start
mycelium peers --json
mycelium scan
mycelium services --json
```

Rendezvous export expires after two minutes, refreshed every 30 seconds. Import
rejects expired/future data. Explicitly imported seeds persist across restarts;
their old addresses are connection hints, **not fresh availability evidence**.
Re-export/import when addresses change. Only one side needs an outgoing seed.
QR enrollment claims and automatic refresh of seed hints are follow-up work.

## Trust and transport

The Iroh transport key is separately generated and retained in
`$MYCELIUM_HOME/iroh-secret.key` (0600); it is not the peer signing key or a human
identity. The underlying connection pins the Iroh endpoint key. Inner mTLS
then verifies the existing fleet CA and certificate SAN; the existing gossip
stream retains signed envelopes and transport-certificate binding checks.
No accept-all TLS verifier or new access authority exists.

`iroh-sync.json` is strict, bounded JSON, with at most 32 unique seeds:

```json
{"public_relays":false,"seeds":[]}
```

Public n0 relays are opt-in via `public_relays: true` followed by restart.
With them disabled, this slice requires reachable direct addresses (LAN or
an existing routed overlay). WAN/NAT hole-punch and relay behavior has not
been qualified across the fleet. Public DNS endpoint lookup/publication and
UPnP/PCP/NAT-PMP port mapping are disabled. Iroh does not deploy WireGuard.

Incoming sync is capped at 32 sessions; QUIC permits one bidirectional stream
and no unidirectional streams per connection. Handshake stages time out after
15 seconds; outgoing retries back off from 1 to 60 seconds. Gossip retains its
existing digest cadence and bounded batches, with a 1 MiB input frame limit
enforced before allocation grows beyond the bound.

Runtime-owned `iroh-sync-endpoints.json` publishes expiring leases through the
existing Iroh discovery projection on `scan`; application-owned
`iroh-endpoints.json` remains untouched. The public rendezvous file is separate
from enrollment and credentials. Removing the sync configuration and
restarting disables the runtime; retain the transport key for stable identity.

## Verification

```sh
cargo check -p mycelium-cli --features iroh-sync --tests
cargo test -p myceliumd --features iroh-sync iroh_sync
cargo test -p myceliumd peer_framing_bounds_and_cancellation
```

Tests use isolated loopback Iroh endpoints and freshly generated test mTLS
certificates; they do not need relays, fleet credentials, or production peers.
