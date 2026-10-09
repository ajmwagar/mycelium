# Application-owned service leases

Mycelium observes an optional `application-services.json` file in its home directory
during the existing scan. The application owns the file and service lifecycle;
Mycelium owns observation, topology provenance and gossip. No application protocol
adapter, proxy or permission issuer is introduced into Mycelium.

The document uses `fpl-resource-observation::ServiceCatalog` schema version 1.
Each observation must name the local mesh node as its provenance observer. An
optional `node_id` attribute must agree. Original observation/expiry timestamps
are preserved, with positive TTL at most 300 seconds. Expired entries disappear;
scanning never renews them. IDs must be unique and bounded. The file is limited to
64 KiB, 128 observations and 8 KiB per observation.

Endpoints may use HTTP, HTTPS, TCP, QUIC or Iroh schemes. Credentials, queries and
fragments are rejected. Loopback addresses remain loopback addresses, not guessed
remote routes. Applications must keep credentials and secrets out of attributes:
these observations are inventory metadata carried to mesh peers, not secret storage.

## Manual runbook

1. Have the local application atomically publish the shared catalog to its dedicated
   owner file, using private permissions and the canonical local node identity.
2. Run the normal Mycelium scan. Malformed, future-dated, wrong-owner or oversized
   documents produce a scan warning rather than a partial application catalog.
3. Inspect the service catalog for the application's kind, owner and original expiry.
   Observations use the existing topology advertisement and signed gossip path.
4. Renew leases in the application, not in Mycelium. Remove the owner file to disable
   future observation. Existing gossiped leases expire at their original timestamps;
   file removal is not immediate distributed revocation.

Consumers must enforce their own access policy. A service lease is availability
evidence, not an ACL, and a secure gateway does not secure a native LAN device.

## Verification

`cargo check -p myceliumd --tests`, then `cargo test -p myceliumd local_services`.
Tests cover bounds, credentials, identity, expiry, duplicate IDs, topology round-trip
and service projection. An ignored interop test consumes an actual Unibus-exported
document via `FPL_TEST_OWNER_CATALOG_FILE`; it requires that fixture explicitly and
does not add a Unibus dependency to Mycelium.
