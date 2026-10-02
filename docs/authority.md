# Shared authority

Mycelium uses one offline-verifiable authority graph for access records and
software promotion. The root key is configured on every peer by public key ID:

```sh
export MYCELIUM_AUTHORITY_KEYS=<root-public-key-id>
```

The root private key is not distributed. It signs bounded delegation and
revocation statements; those signed records are gossiped like other Mycelium
observations. Peers can therefore authorize work while Neo, an IdP, or a WAN
connection is unavailable.

Capabilities are intentionally narrow:

- `access_publish`: sign SSH/OIDC access grants and access revocations.
- `release_publish`: publish Mycelium's own release manifests.
- `package_promote`: publish named packages, optionally constrained by channel
  and target triple.

Discovery and peer identity do not confer authority. An enrolled peer may
transport records, but only a root or an active delegation may create them.
Delegation is one level deep in v1; delegated keys cannot delegate again.

## Runbook

Generate a 32-byte Ed25519 authority key with the existing key generator and
put only its reported public key ID in `MYCELIUM_AUTHORITY_KEYS`:

```sh
mycelium access keygen --path "$HOME/.mycelium/authority.key" --write
```

Create a statement from an example, replace the IDs and validity timestamps,
then publish it:

```sh
mycelium authority delegate \
  --statement docs/examples/authority-package-delegation.json \
  --signing-key "$HOME/.mycelium/authority.key" \
  --write
```

Inspect converged authority records or explain an authorization decision:

```sh
mycelium authority list
mycelium authority explain access.publish <signer-id>
mycelium authority explain package.promote <signer-id> \
  --name unibus --channel stable --target aarch64-unknown-linux-musl
```

Revoke by publishing a root-signed revocation. Revocation immediately removes
the delegated signer's retained grants and packages from active views:

```sh
mycelium authority revoke \
  --statement docs/examples/authority-revocation.json \
  --signing-key "$HOME/.mycelium/authority.key" \
  --write
```

`MYCELIUM_ACCESS_KEYS` and `MYCELIUM_RELEASE_KEYS` remain supported as explicit
legacy roots during migration. `authority explain` reports `legacy` when one of
those settings authorized the operation. New enrollment bundles also propagate
`MYCELIUM_AUTHORITY_KEYS`.

Fab/Fabd may produce builds, but Mycelium does not depend on it at runtime.
Mycelium authorizes, transports, caches, and atomically selects package
artifacts. A bounded native lifecycle adapter may request a restart, verify
health, and roll back; general process supervision remains with systemd,
launchd, or the host's chosen supervisor. Bifrost owns inference and is not a
service-lifecycle dependency.
