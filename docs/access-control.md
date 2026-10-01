# Mycelium access control

Mycelium separates four concerns so no peer becomes a mandatory central
control plane:

1. Peer mTLS authenticates mesh transport.
2. An offline access authority signs grants and revocations.
3. Peers gossip and converge those signed records.
4. OpenSSH and OIDC adapters translate at narrow system boundaries.

OIDC tokens and SSH CA private keys are never gossiped. A node may transport an
access record, but only an authority in `MYCELIUM_ACCESS_KEYS` can create one.
Revocations are durable and win regardless of message arrival order.

## Manual runbook

Create the two independent authorities:

```sh
mycelium access keygen --path .mycelium/access.key --write
mycelium access ssh ca-init --path .mycelium/ssh/user_ca --write
```

Publish a signed grant whose `principal` is stable. For OIDC identities,
Mycelium derives `oidc:<issuer>#<subject>` after verifying the provider token.
The grant must contain a unique SSH certificate `serial`, at least one
`unix_users` principal, validity bounds, and the permitted `ssh_public_keys`.

```sh
mycelium access publish \
  --statement grant.json \
  --signing-key .mycelium/access.key \
  --write

OIDC_TOKEN='...' mycelium access oidc verify \
  --issuer https://identity.example \
  --audience mycelium \
  --token-env OIDC_TOKEN \
  --json

mycelium access ssh issue \
  --grant grant-1 \
  --public-key ~/.ssh/id_ed25519.pub \
  --ca .mycelium/ssh/user_ca \
  --path ~/.ssh/id_ed25519-cert.pub \
  --ttl 8h \
  --write
```

Certificate lifetime is capped by the signed grant. Issuance fails if the
grant is missing, inactive, expired, revoked, has no Unix principal, or does
not contain the presented public key.

Publish a revocation, then deterministically derive an OpenSSH KRL and a host
configuration bundle from the converged state:

```sh
mycelium access publish \
  --statement revoke.json \
  --signing-key .mycelium/access.key \
  --write

mycelium access ssh krl \
  --ca-public .mycelium/ssh/user_ca.pub \
  --path .mycelium/ssh/revoked.krl \
  --write

mycelium access ssh host-bundle \
  --ca-public .mycelium/ssh/user_ca.pub \
  --krl .mycelium/ssh/revoked.krl \
  --path .mycelium/ssh/host-bundle \
  --write
```

The host bundle is deployment-driver-neutral. Its manifest maps inputs to
`/etc/ssh`, requires `sshd -t`, and allows reload only after validation. It
does not disable existing authentication methods in this first slice.

## OIDC boundary

`access oidc verify` uses standard discovery and JWKS. It accepts any provider
that supplies a matching issuer and asymmetric signing key, then validates
signature, key ID, issuer, audience, subject, and expiry. The only output is a
normalized identity contract (`principal`, issuer, subject, optional email,
groups, and expiry). The access authority remains responsible for policy and
signing; the OIDC adapter cannot mint a grant by itself.
