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

Back up both private keys offline. Ordinary peers receive only the access
signer ID through `MYCELIUM_ACCESS_KEYS` and the SSH CA public key through a
host bundle.

Publish a signed grant whose `principal` is stable. For OIDC identities,
Mycelium derives `oidc:<issuer>#<subject>` after verifying the provider token.
The grant must contain a unique SSH certificate `serial`, at least one
`unix_users` principal, validity bounds, and the permitted `ssh_public_keys`.
Start from [`examples/access-grant.json`](examples/access-grant.json), replace
the example key with the exact contents of the user's `.pub` file, and choose
fresh validity timestamps and a never-reused serial.

```sh
mycelium access publish \
  --statement docs/examples/access-grant.json \
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

The verify result and the grant are deliberately separate. Compare the
returned `principal` with the grant's `principal`, then let the access
authority publish the policy decision. Mycelium does not currently exchange a
verified OIDC token for a grant automatically.

Certificate lifetime is capped by the signed grant. Issuance fails if the
grant is missing, inactive, expired, revoked, has no Unix principal, or does
not contain the presented public key.

Publish a revocation, then deterministically derive an OpenSSH KRL and a host
configuration bundle from the converged state:

```sh
mycelium access publish \
  --statement docs/examples/access-revocation.json \
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

### Install or roll back a host bundle

The bundle command does not mutate the host. A Linux deployment driver—or a
human following this runbook—installs it transactionally:

```sh
bundle=.mycelium/ssh/host-bundle
sudo install -d -m 0755 /etc/ssh/mycelium /etc/ssh/sshd_config.d
sudo cp -a /etc/ssh/mycelium /etc/ssh/mycelium.pre-mycelium
sudo install -m 0644 "$bundle/user_ca.pub" /etc/ssh/mycelium/user_ca.pub
sudo install -m 0644 "$bundle/revoked.krl" /etc/ssh/mycelium/revoked.krl
sudo install -m 0644 "$bundle/60-mycelium-access.conf" \
  /etc/ssh/sshd_config.d/60-mycelium-access.conf
sudo sshd -t
sudo systemctl reload sshd || sudo systemctl reload ssh
```

Keep the current SSH session open and establish a second certificate-backed
session before considering the change complete. If validation or the second
login fails, remove `60-mycelium-access.conf`, restore the saved
`/etc/ssh/mycelium` directory, run `sshd -t`, and reload SSH again. A driver
must implement the same order: stage, validate, atomically install, reload,
then probe a new session; never reload an invalid configuration.

Inspect an issued certificate and confirm a revoked certificate is present in
the KRL with:

```sh
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub
ssh-keygen -Q -f .mycelium/ssh/revoked.krl ~/.ssh/id_ed25519-cert.pub
```

The KRL query exits successfully when the certificate is not revoked and
non-zero when it is revoked.

## OIDC boundary

`access oidc verify` uses standard discovery and JWKS. It accepts any provider
that supplies a matching issuer and asymmetric signing key, then validates
signature, key ID, issuer, audience, subject, and expiry. The only output is a
normalized identity contract (`principal`, issuer, subject, optional email,
groups, and expiry). The access authority remains responsible for policy and
signing; the OIDC adapter cannot mint a grant by itself.
