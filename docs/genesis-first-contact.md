# Physical PXE first contact

PXE delivers boot artifacts; it does not establish the identity or authority of
the machine requesting them. Neither a MAC address, a DHCP lease, a source IP,
nor possession of a public boot-intent digest authorizes Mycelium enrollment.
HTTPS authenticates the server and protects transport; it does not by itself
authorize the client to receive an enrollment claim.

## Implemented boundary

Genesis's current HTTP listener serves profiles, intents, receipts, artifacts,
and non-secret iPXE scripts. It has no claim-delivery endpoint. Do not place
claims in its public artifact store or infer that `https` in a profile makes
the running listener support TLS.

Mycelium already owns invitations and redemption:

- `invite.rs` stores a hash of the random invitation secret, its expiry,
  remaining uses, peer name, site, roles, and seed peers.
- `oidc_gateway.rs` checks expiry and remaining uses, issues the credentials,
  and persists consumption before returning the successful response. Its
  mutex serializes requests within one gateway process; this is not a
  cross-process transactional guarantee. Do not run multiple writers against
  the same JSON invitation store.
- `enroll.rs` verifies the CSR signature and requires its subject to be
  exactly the invitation's expected peer name. The peer key is generated on
  the guest, never copied from an authority.
- `setup --claim-file` accepts a bounded, owner-only claim file and removes it
  only after successful setup. The existing QEMU protected-media adapter
  stages that file in `/run` and then invokes the same setup path.

An invitation's name binding is not proof of physical hardware identity. The
current invitation does not bind an install-intent digest or TPM key. A secure
physical-install adapter must not claim those checks exist.

## Initial trust decision

The first physical target needs an explicitly selected trusted delivery path:
protected USB or BMC virtual media, a manual out-of-band claim, or provisioned
hardware attestation. None is inferred from ordinary PXE discovery. A generic,
publicly available initramfs must not contain a reusable secret.

For a protected-media experiment, the media can carry the existing one-use
Mycelium pairing claim rather than inventing a second bootstrap credential.
The authority retains expiry and replay enforcement. The intended-install
binding must come from that trusted provisioning operation and, if stronger
hardware proof is required, a separately specified verification step.

Until this trust choice is made, physical automatic enrollment remains
unimplemented and must fail closed. The QEMU guest and its working update
flow do not depend on this decision.

## HTTPS integration requirements

The pairing listener currently uses plain TCP HTTP even when its advertised
URL is HTTPS. HTTPS therefore needs an explicitly configured TLS terminator
or an implemented TLS listener; advertising a URL is not transport security.
Its private-network HTTP allowance must not be reused as the physical-PXE
security policy.

The future adapter must validate the configured HTTPS server's certificate
chain and expected hostname using trust installed through the selected trusted
channel. Never learn that trust from the same unauthenticated PXE response.
Use no TLS-verification bypass, no HTTP downgrade, and no redirect to a
different server. The existing default redirect-enabled redemption client
needs review before being used for this path.

Keep enrollment issuance and one-use consumption in Mycelium. Genesis owns
delivery/installation coordination only. Do not build a second invitation
database, copy authority private keys onto the installer, or expose claims
through kernel arguments, TFTP, public HTTP, environment variables, access
logs, command tracing, or diagnostic output.

## Manual runbook and acceptance evidence

An operator first verifies the selected boot artifacts and intended target,
then creates a short-lived, one-use peer invitation with the expected peer
name, site, roles, and certified reachable seed addresses. They transfer its
claim through the selected trusted channel, stage it owner-only in `/run`,
and invoke the existing `mycelium setup --claim-file PATH --system-service`
path. Only the owner-only file path, not its contents, belongs in a command.

Completion requires evidence that the guest's locally generated key enrolled
as the expected peer, its service is healthy, and the staged claim is removed.
Expired and replayed claims must not issue credentials. A CSR for a different
peer name must be rejected without consuming a valid invitation. A wrong
server certificate/hostname, insecure URL, unexpected redirect, and wrong
install authorization must all fail before sending a secret or issuing an
identity. A consumed claim after a lost response requires inspection and a
new invitation; it must not silently become reusable.

These are acceptance requirements for physical enrollment, not a statement
that the physical-PXE handoff has been shipped or tested.
