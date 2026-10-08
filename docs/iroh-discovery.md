# Optional Iroh endpoint discovery

For Mycelium's own optional authenticated transport, see [Iroh peer sync](iroh-sync.md).
This discovery adapter remains observation-only and does not link the Iroh runtime.

The discovery adapter observes application-published Iroh endpoints. It does not start an
Iroh endpoint, manage relays, transfer blobs, grant room admission, enroll GPU
workers, or replace Tailscale/WireGuard. This slice is discovery, not compute
transport qualification.

Build the host with `cargo build -p mycelium-cli --features
myceliumd/iroh-discovery`. Without this feature, no Iroh runtime or discovery
adapter is linked. The adapter itself has no Iroh/network dependency.

## Owner publication and verification

The endpoint-owning application atomically writes
`$MYCELIUM_HOME/iroh-endpoints.json` (normally `~/.mycelium/iroh-endpoints.json`).
Version 1 has this shape; replace values with the actual bound endpoint:

```json
{
  "schema_version": 1,
  "endpoints": [{
    "id": "compute-worker",
    "endpoint_id": "<64 lowercase hexadecimal public-key characters>",
    "alpns": ["<actual application ALPN>"],
    "direct_addresses": ["192.168.1.48:4000"],
    "relay_urls": ["https://relay.example.net/"],
    "observed_at": 1791440000,
    "expires_at": 1791440300
  }]
}
```

Times are Unix seconds. Renew only while the actual endpoint is available;
the maximum lease is 300 seconds. Do not publish placeholder keys, inferred
ports, private keys, bearer tokens, or invitations. Address hints are not proof
of reachability. ALPNs are bounded UTF-8 strings in this contract.

1. Start the actual application endpoint and write its lease.
2. Run `mycelium scan --json`; malformed documents appear in scan warnings.
3. Run `mycelium services --json` and select fresh `kind: "iroh"` observations.
   Verify `endpoint_id`, ALPNs, direct/relay hints, origin, and expiry.
4. Verify the same projection from a connected observer after topology gossip.
5. Stop renewal: the observation becomes stale at its original expiry, even if
   scans continue. Removing the file disables future publication; already
   gossiped leases expire rather than disappearing immediately.

The file is bounded to 64 KiB, at most 32 endpoints, 16 ALPNs and direct addresses
per endpoint, and four credential-free HTTPS relay hints. Missing configuration
is disabled; malformed input fails visibly. Services have stable identities
bound to the observing Mycelium node and application endpoint name.

Existing signed topology gossip carries the observations. They are owner
assertions, not independently verified Iroh handshakes. Applications must pin
the Iroh key, verify enrollment/credentials, and authorize their protocol before
accepting commands or inference traffic. A public endpoint ID is not an access
grant, and applications need not depend on Mycelium to connect explicitly.

## GPU integration boundary

Yggdrasil already permits no mesh configuration. Its Bifrost registration still
advertises HTTP inference/control/metrics origins, and Bifrost routes using HTTP
base URLs. Discovery alone does not make those origins reachable without a VPN.

The next transport slice should expose a narrowly authorized worker-side Iroh
protocol and a gateway-side dialer, preserving existing node enrollment,
inference authentication, streaming responses, cancellation, health and owner
policy. Prefer this explicit boundary over a generic unauthenticated HTTP tunnel.
Advertise the real ALPN only after that protocol exists; no fake compute service
is installed by this discovery adapter. Bulk artifacts remain storage-owned.

Agora and Titan need x86_64 Linux artifacts; Spark needs aarch64. Build on Agora,
cross-build Spark, retain rollback binaries, and verify daemon/gossip health
after each staged restart before moving to the next host. Do not remove an
existing Tailscale installation until an authorized end-to-end inference test
passes without relying on its addresses.

## Deployment verification: 2026-10-08

Discovery-enabled builds were built on Agora and installed on Agora (ajmwagar),
Titan (avery), and DGX Spark (fpladmin). Spark was cross-built on Agora for
`aarch64-unknown-linux-gnu` and its dynamic libraries resolved on the real host.
All three supervised daemons responded to the Iroh service-catalog query.
No endpoint-owning application has published a lease yet; catalogs were empty,
not populated with fake compute endpoints. Existing peer keys were retained.

Each host retains `.mycelium/bin/mycelium.pre-iroh-20261008` for rollback:
stop `mycelium.service`, copy that artifact back to `.mycelium/bin/mycelium`,
and start the service. Avoid queries that auto-spawn a daemon during restart;
use `MYCELIUM_NO_AUTOSTART=1` for verification after the supervised socket is up.

The discovery crate and core passed 57 tests, existing daemon service projection
passed six tests, and the isolated source passed a locked CLI check with the
feature enabled. The locked build also corrects one existing obsolete
`mycelium-driver-edgeos` dependency entry for the Unifi driver. Unrelated local
firmware and service-recognition work was excluded from the deployed source.

Iroh handshakes, NAT traversal, relay fallback, cross-site GPU requests, and
tailnet-free enrollment are not qualified by these discovery checks. Marbles
task registration was unavailable (HTTP 401); no claim or delivery status was
fabricated.

The deployment check also found Spark's existing `MYCELIUM_PEERS` is empty:
its daemon currently sees only itself. Agora and Titan have populated peer
views. No seed, trust root, or allowlist was changed in this slice. Spark's
cross-host gossip must be connected/verified before claiming fleet-wide endpoint
discovery; installing the driver alone does not establish that connection.
