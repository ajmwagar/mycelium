# Portable fleet identity

`mycelium_peer_protocol::identity` provides transport-independent identity
proofs. It is a library foundation, not an active replacement for the daemon's
inner mTLS. Enrollment issuance, persistent verification state, gossip
distribution and runtime Iroh handshake integration remain to be wired.

## Trust boundary

The fleet authority signs membership of the machine's actual Ed25519 gossip
key. That machine signs its Iroh endpoint keys. A machine can have independent
endpoint records for Mycelium and Unibus without either daemon depending on
the other's implementation. Existing transport credential fields are reused.

Endpoint identity contains no ALPN, role, human ownership or ACL. Permission
changes do not require reissuing endpoint keys. Successful verification returns
an authenticated machine ID, not permission to run a protocol or operation.
OIDC authenticates people separately; it does not become a device signing key.

Every signed record covers its fleet, signer, schema version and statement under
the `mycelium/fleet-identity` signature domain. Keys use canonical lowercase
hex. Membership and endpoints have explicit validity intervals and generations.
Credential IDs must be unique within a peer; membership and endpoint IDs must
be distinct. Revocations name both the peer and credential ID, preventing
cross-peer collisions. Authority signatures can revoke membership or endpoints;
peer signatures can revoke only their own endpoints.

## Consumer runbook

1. Obtain the fleet ID and approved membership issuer keys through the existing
   trusted enrollment/delegation path, never from the connecting machine.
2. Load retained, verified revocations and persisted generation floors scoped
   to the peer and endpoint slot. Validate freshness of the local policy state.
3. Read the remote endpoint key from the actual Iroh handshake.
4. Pass membership, endpoint proof, handshake key and trusted local context to
   `verify_iroh_peer`. Reject invalid signatures, wrong fleets, expired proofs,
   retired generations, revoked credentials and substituted handshake keys.
5. Evaluate separately authenticated policy for the requested protocol/action.
   Discovery and successful authentication do not grant access.

Consumers must durably retain revocations and generation floors across reboot;
the library does not persist them. Revocation tombstones do not expire when the
target credential expires. A disconnected consumer cannot learn new revocations:
its existing policy-freshness rules must bound acceptance rather than silently
trust stale state forever. Offline operation is bounded by proof expiry and
policy freshness, not dependent on a live hosted control plane.

Do not remove inner mTLS until issuance, storage, distribution, renewal and
handshake integration are tested end to end. The enterprise control plane can
manage these same contracts; it must not introduce a second mandatory identity
system or become a dependency for established data-plane connections.
