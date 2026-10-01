# Mycelium

**A distributed control plane for the networks and hardware you already own.**

Mycelium discovers physical topology, normalizes devices from different vendors,
and coordinates health, releases, and bounded access without requiring a central
controller. It is Rust-first, scriptable, and designed to fail closed around
mutating operations.

> Mycelium is usable today, but it is still pre-1.0. Read operations are the
> safest place to begin. Every mutation requires an explicit `--write`, and
> supported operations offer `--dry-run` so the proposed action is visible first.

## What works today

| Area | Current support |
| --- | --- |
| Discovery | SNMP, mDNS/DNS-SD, SSDP/UPnP, Linux, Darwin, and Tailscale observations |
| Topology | Multi-site/LAN inventory, physical switch-port attachment, services, routes, and link transport |
| Hardware | NETGEAR FastPath, EdgeOS, UniFi AP/controller, Redfish/iLO, Linux, and Darwin drivers |
| Desired state | Stable logical networks, imported allocations, drift reports, VLAN and forwarding primitives |
| Peer mesh | Signed observations, mTLS transport, health streaming, and target-aware P2P updates |
| Access | Signed grants/revocations, OIDC verification, short-lived OpenSSH certificates, and KRL generation |
| Early boot | PXE/NBDE reachability planning for Tang/Clevis deployments |

Replacement firmware remains experimental research and is not part of the
supported host build.

## Quick start

For a first-time user, the installer builds the CLI and starts browser-based
OIDC enrollment. `MYCELIUM_GATEWAY` can select any compatible deployment.

```sh
curl --proto '=https' --tlsv1.2 -fsS \
  https://raw.githubusercontent.com/ajmwagar/mycelium/master/install.sh | sh
```

After installation, enrollment can be repeated explicitly with
`mycelium setup --gateway https://sso.fpl.dev`.

An administrator can instead run a temporary pairing listener when OIDC is not
appropriate. The self-contained claim carries the rendezvous URL and a
high-entropy secret; the authority stores only its hash. The listener exits
after successful redemption or expiry. Private-network HTTP is supported for
direct pairing, while public rendezvous URLs must use HTTPS.

```sh
# Authority host; keep this process open while the other user joins:
mycelium pair --name buddy --unix-user operator \
  --ttl 15m --credential-ttl 8h

# New user machine:
curl --proto '=https' --tlsv1.2 -fsS \
  https://raw.githubusercontent.com/ajmwagar/mycelium/master/install.sh | \
  sh -s -- --claim MYC1-REPLACE-WITH-THE-PAIRING-CLAIM
```

Peer membership is separate from SSH access. A peer claim creates its private
key on the joining machine, sends only a CSR to the temporary authority, and
installs the returned mTLS identity plus mesh seeds:

```sh
mycelium pair --kind peer --name james --site home \
  --peer 100.120.101.5:7443 --unix-user mames --role home-operator \
  --advertise http://100.120.101.5:8788 --ttl 15m
```

The recipient passes the printed claim to `mycelium setup --claim ...` (or the
installer's `--claim` option). Joining as a peer does not itself grant SSH.
Roles are carried as signed SSH certificate principals; each host opts into
roles with `host-bundle --allow USER=ROLE`. A host with no mapping denies all
Mycelium certificate roles while leaving its pre-existing SSH methods intact.

Requirements: a current stable Rust toolchain and the native tools required by
the drivers you choose (for example OpenSSH and SNMP utilities).

Install directly from GitHub:

```sh
cargo install --git https://github.com/ajmwagar/mycelium.git \
  --package mycelium-cli --locked
mycelium drivers
```

For a pinned checkout, build `mycelium-cli` as shown below and place
`target/release/mycelium` on `PATH`.

```sh
git clone https://github.com/ajmwagar/mycelium.git
cd mycelium
cargo build --release -p mycelium-cli

# The CLI starts its local daemon on demand.
./target/release/mycelium drivers
./target/release/mycelium devices
./target/release/mycelium topology
```

Add read-only observation points, scan, and inspect the unified map:

```sh
mycelium add pris --driver linux --user ajmwagar
mycelium add 192.168.1.2 --driver snmp --password-env SNMP_COMMUNITY
mycelium scan
mycelium map
```

Credentials are referenced by environment-variable name and are not persisted
in inventory. Use a dedicated `MYCELIUM_HOME` when evaluating against a test
network.

## Design

- One shared representation; vendor drivers translate capabilities at the edge.
- Integrate existing systems instead of replacing or reimplementing them.
- Derive topology and configuration from observed source data whenever possible.
- Keep workflows deterministic; Lua plugins run through bounded host APIs.
- Require explicit authorization for mutations and preserve a human-readable plan.
- Treat overlapping private address space as site-scoped, not globally unique.

## Early-boot paths and NBDE

Mycelium can evaluate whether observed topology supports an early-boot path
to Tang endpoints. It distinguishes direct, routed, and unverified paths; a
routed path remains a warning until initramfs addressing and firewall policy
are verified. Planning is read-only and does not execute Clevis:

```sh
mycelium boot-path <device> --target http://192.168.20.8:7500
mycelium nbde plan <device> \
  --tang http://192.168.20.8:7500 \
  --tang http://192.168.99.8:7500 \
  --threshold 2
```

Tang endpoints currently use literal IP addresses deliberately: boot-time DNS
is not assumed. A later enrollment workflow will call the system Clevis/Tang
tools and retain a passphrase recovery slot rather than reimplementing NBDE.

## Intelligent SSH hops

For a service reachable through an inventory gateway, Mycelium derives the
hop from the target's observed segment and gateway:

```sh
# Plan only.
mycelium tunnel 192.168.99.12:80 --local-port 8080

# Open in the foreground; Ctrl-C closes it.
mycelium tunnel 192.168.99.12:80 --local-port 8080 --write
```

The daemon returns SSH arguments and an environment-variable name only. The
secret stays in the CLI environment and is passed to `sshpass` via `SSHPASS`,
never argv. `--via DEVICE` overrides inference when multiple paths are valid.

## Peer mesh

Every `myceliumd` is a symmetric peer. It collects local Linux or Darwin
health, signs observations with a persistent Ed25519 identity in
`$MYCELIUM_HOME/peer.key`, and answers `mycelium peers` from its locally
converged view. There is no required controller.

Direct peer links are optional and mutually authenticated. Configure any node
as a listener, a dialer, or both:

```sh
export MYCELIUM_PEER_LISTEN=0.0.0.0:7443       # optional
export MYCELIUM_PEERS=pris.example:7443,neo.example:7443  # optional seeds
export MYCELIUM_PEER_CA=/etc/mycelium/ca.pem
export MYCELIUM_PEER_CERT=/etc/mycelium/node.pem
export MYCELIUM_PEER_KEY=/etc/mycelium/node-key.pem
# Optional comma-separated Ed25519 node IDs allowed as observation origins.
export MYCELIUM_PEER_ALLOW=0123abcd...,4567efab...
mycelium daemon start
mycelium peers
```

## Peer enrollment and updates

Enrollment uses one locally held CA to issue a distinct mutual-TLS identity for
each peer. Bundles contain no CA signing key. Installation stages the peer and
its native user-service definition, but deliberately does not start it:

```sh
mycelium enroll init --write
mycelium enroll issue pris --site lab --address pris \
  --target x86_64-unknown-linux-gnu --binary ./mycelium \
  --peer neo.example:7443 --write

# On pris, after transferring its bundle:
mycelium enroll install --bundle ./pris --write
systemctl --user daemon-reload
systemctl --user enable --now mycelium
```

Darwin installations write `~/Library/LaunchAgents/dev.fpl.mycelium.plist`
instead. Release manifests and artifacts are signed independently of the mesh
CA, so transport membership does not grant permission to publish executable
code. Peers fetch verified artifacts from one another, and `mycelium update
apply --write` retains and automatically restores the prior executable if the
new daemon fails its health check.

Compilation belongs to the external build pipeline (for example Fab). The
pipeline hands Mycelium a JSON release-set manifest whose relative binary paths
are resolved from the manifest's directory:

```json
{
  "version": "0.1.1",
  "channel": "canary",
  "artifacts": [
    { "target": "aarch64-apple-darwin", "binary": "dist/mycelium-darwin-arm64" },
    { "target": "aarch64-unknown-linux-gnu", "binary": "dist/mycelium-linux-arm64" },
    { "target": "x86_64-unknown-linux-musl", "binary": "dist/mycelium-linux-x86_64" }
  ]
}
```

`mycelium releases publish-set --manifest release-set.json --signing-key
release.key --write` validates, hashes, and signs every artifact before
publishing any target. Peers may cache and relay every artifact, while update
selection remains target-specific.

## Distributed access state

Access authorities are independent from peer and release identities. Peers
accept access statements only from public keys listed in
`MYCELIUM_ACCESS_KEYS`, then relay those signed statements unchanged. Grants
can represent multiple people, devices, roles, scopes, Unix accounts, and SSH
public keys. Revocations are durable statements rather than deletion events;
matching revocations always make a grant inactive regardless of gossip order.

```sh
mycelium access keygen --path .mycelium/access.key --write
export MYCELIUM_ACCESS_KEYS=<reported-signer-id>
mycelium access publish --statement grant.json \
  --signing-key .mycelium/access.key --write
mycelium access publish --statement revocation.json \
  --signing-key .mycelium/access.key --write
mycelium access list
```

OIDC-backed grants bind issuer, subject, and audience to Unix principals and
optionally permit a valid JWT holder to certify a presented SSH key. The
JWT must be valid during exchange. The resulting SSH certificate is an
independent, bounded credential that never outlives its requested TTL or the
signed grant, so an IdP outage does not immediately terminate existing access.

### Join with OIDC

The SSH CA stays on an authority host. Run the gateway on loopback and expose
it only through an HTTPS reverse proxy:

```sh
mycelium access oidc gateway \
  --listen 127.0.0.1:8787 \
  --issuer https://identity.example \
  --audience mycelium \
  --client-id mycelium \
  --client-secret-env MYCELIUM_OIDC_CLIENT_SECRET \
  --callback-url https://mycelium-access.example/v1/oidc/callback \
  --ca "$MYCELIUM_HOME/ssh/user_ca" --write
```

After an administrator publishes the user's signed grant, the user installs
the CLI and exchanges a current ID token plus their public key:

```sh
mycelium access oidc join \
  --gateway https://mycelium-access.example \
  --public-key ~/.ssh/id_ed25519.pub \
  --certificate ~/.ssh/id_ed25519-cert.pub \
  --ttl 8h --write

mycelium access ssh client-config \
  --host mycelium-lab --hostname lab.example --user buddy \
  --identity ~/.ssh/id_ed25519 \
  --certificate ~/.ssh/id_ed25519-cert.pub \
  --path ~/.ssh/mycelium-lab.conf --write
```

Include the generated fragment from `~/.ssh/config`. Provider configuration,
client credentials, grants, CA material, certificates, and runtime inventory
belong in deployment state, never the source tree. The gateway reloads current
grant/revocation state for every request and never returns the CA key.

An existing login CLI can supply the token through a provider-neutral
credential process. Store this deployment configuration outside the repository
at `$MYCELIUM_HOME/auth-providers.json`:

```json
{
  "providers": {
    "company-sso": {
      "issuer": "https://identity.example",
      "audience": "mycelium",
      "credential_process": [
        "fpl", "auth", "token", "--audience", "mycelium", "--json"
      ]
    }
  }
}
```

Then use `mycelium access oidc join --provider company-sso ...`. Mycelium runs
the argv array directly without a shell and independently verifies the returned
JWT against discovery, JWKS, issuer, and audience before sending it to the
certificate gateway.

### Enable certificate SSH on a host

Once an enrolled host trusts the Mycelium SSH CA and the user has a current
certificate at `$MYCELIUM_HOME/ssh/user-cert.pub`, normal access is one command:

```sh
mycelium ssh lab-node
mycelium ssh lab-node -- uname -a
```

The daemon derives the destination, Unix user, port, and optional ProxyJump
from inventory targets such as `host:2222@gateway`. The CLI prefers
`$MYCELIUM_HOME/ssh/<device-id>-cert.pub`, then the shared
`$MYCELIUM_HOME/ssh/user-cert.pub`. It uses only the selected identity and
certificate, so missing material fails loudly instead of silently falling back
to unrelated agent keys. Override paths with `--key` and `--certificate`, or
set `MYCELIUM_SSH_IDENTITY` and `MYCELIUM_SSH_CERTIFICATE`.

Host CA trust is a privileged bootstrap/reconciliation action. Mycelium
generates the host bundle and an optional narrowly scoped client fragment; it
does not silently modify `sshd` or `~/.ssh/config`. Keep an existing SSH session
open while installing the bundle, validate before reload, and prove a second
certificate-only connection before closing the original session.

```sh
# Authority: create these once, then keep the private keys off ordinary peers.
mycelium access keygen --path "$MYCELIUM_HOME/access.key" --write
mycelium access ssh ca-init --path "$MYCELIUM_HOME/ssh/user_ca" --write

# Publish a grant prepared from docs/examples/access-grant.json, then issue.
mycelium access publish --statement grant.json \
  --signing-key "$MYCELIUM_HOME/access.key" --write
mycelium access ssh issue --grant GRANT_ID \
  --public-key ~/.ssh/id_ed25519.pub \
  --ca "$MYCELIUM_HOME/ssh/user_ca" \
  --path "$MYCELIUM_HOME/ssh/user-cert.pub" --ttl 8h --write

# Derive the host trust bundle from the same converged authorization state.
mycelium access ssh krl --ca-public "$MYCELIUM_HOME/ssh/user_ca.pub" \
  --path "$MYCELIUM_HOME/ssh/revoked.krl" --write
mycelium access ssh host-bundle \
  --ca-public "$MYCELIUM_HOME/ssh/user_ca.pub" \
  --krl "$MYCELIUM_HOME/ssh/revoked.krl" \
  --allow mames=home-operator \
  --path "$MYCELIUM_HOME/ssh/host-bundle" --write
```

Copy the bundle to an enrolled Linux or macOS host, then apply it in one command:

```sh
sudo -E mycelium access ssh host-apply \
  --bundle "$MYCELIUM_HOME/ssh/host-bundle" --write
```

The command retains a rollback copy under `/etc/ssh`, runs `sshd -t`, reloads
only a valid configuration, and restores the prior files if validation or
reload fails. The equivalent manual break-glass procedure is documented in
[`docs/access-control.md`](docs/access-control.md#install-or-roll-back-a-host-bundle).

`mycelium ssh` does not require OpenSSH client configuration. If direct
`ssh mycelium-lab` compatibility is useful, generate an optional alias:

```sh
mycelium access ssh client-config \
  --host mycelium-lab --hostname lab-node.example.net --user operator \
  --identity ~/.ssh/id_ed25519 \
  --certificate "$MYCELIUM_HOME/ssh/user-cert.pub" \
  --path ~/.ssh/mycelium-lab.conf --write

# One-time client integration; Mycelium prints this instruction too.
printf '%s\n' 'Include ~/.ssh/mycelium-lab.conf' >> ~/.ssh/config
ssh -o BatchMode=yes -o PasswordAuthentication=no mycelium-lab
```

After that optional one-time `Include`, `ssh mycelium-lab` selects the
configured key and current Mycelium certificate. Certificate renewal replaces
the certificate at the same path; the SSH fragment does not need regeneration.

The authority private key stays off ordinary peers. Membership in the mTLS
mesh permits transport only; it does not permit creating access statements.
See [`docs/access-control.md`](docs/access-control.md) for the OIDC verification,
SSH certificate issuance, host installation, validation, and rollback runbook.

The TLS CA authorizes direct peers. Signed observation envelopes preserve
their originating node identity when relayed, use monotonic sequence numbers,
and deterministically retain the newest event per origin. Back up `peer.key`:
it is the node identity and is created with owner-only permissions. A future
Unibus carrier can exchange the same envelopes without changing their trust or
merge semantics.

### Signed peer updates

Release authorization is separate from peer transport identity. Generate an
offline release key, configure its returned public key on peers, then publish a
binary for one target and rollout channel:

```sh
mycelium releases keygen --path /secure/mycelium-release.key --write
export MYCELIUM_RELEASE_KEYS=<public-key-from-keygen>
mycelium releases publish \
  --binary ./target/release/mycelium \
  --signing-key /secure/mycelium-release.key \
  --version 0.2.0 --channel canary \
  --target aarch64-apple-darwin --write
```

Peers exchange only anti-entropy metadata until an authorized release is
missing locally. They then fetch bounded chunks from any connected peer,
resume by offset, and promote the artifact only after verifying its signed
size and SHA-256 digest.

```sh
mycelium update status --channel canary
mycelium update apply --channel canary --write
```

Activation preserves the prior executable, starts the candidate as a daemon,
and requires the local peer RPC to become healthy within ten seconds. Failure
automatically restores and starts the previous executable. Distribution peers
never possess or imply release authority.

## SSH observation points

Ordinary Linux hosts can contribute their interfaces, connected routes, and
neighbor tables without becoming network appliances themselves:

```sh
mycelium add pris --driver linux --user ajmwagar
mycelium add lab-node.example.net --driver linux --user operator
mycelium scan
```

The Linux driver runs a fixed, read-only `iproute2` probe over SSH. It uses
OpenSSH configuration and agent credentials when no password or key is given.
Each observer hostname is also its site identity, so overlapping private
networks are stored separately (`pris/192.168.1.0/24` and
`lab/192.168.1.0/24`) instead of producing false address conflicts.

## Redfish servers

Redfish management controllers expose identity, power state, and thermal
telemetry. Power-on is write-gated and supports dry-run:

```sh
mycelium add 192.168.20.11 --driver redfish --user Administrator --password-env ILO4_PASS
mycelium call ilo-mxq33702q8 server.power-state
mycelium call ilo-mxq33702q8 server.thermal
mycelium call ilo-mxq33702q8 server.power-on --write --dry-run
mycelium console ilo-mxq33702q8
```

Controller passwords remain env-backed; inventory persists only the variable
name. Self-signed controller certificates are accepted, but transport remains
HTTPS-only.

`mycelium console` opens the HPE iLO4 SSH text console in the current terminal.
It accounts for iLO4's legacy SSH algorithms while preserving normal terminal
ownership, so boot prompts such as LUKS can be answered interactively. Press
`Esc` then `(` to leave `textcons` and return to the iLO CLI.

## UniFi access points

The controller driver owns site-wide WLAN, AP, and client state through the
UniFi Network API. Controller credentials remain environment-backed:

```sh
mycelium add 192.168.20.12:8443 --driver unifi-controller \
  --user "$UNIFI_CONTROLLER_USER" --password-env UNIFI_CONTROLLER_PASS
mycelium call <controller-id> wlan.list-ssids
mycelium call <controller-id> unifi.list-aps
mycelium call <controller-id> unifi.list-clients
mycelium call <controller-id> wlan.guest-enable \
  --param 'ssid=Guest' --param enabled=true --write --dry-run
```

The API projection deliberately excludes WLAN passphrases and unrelated
private controller fields. Guest-policy changes require `--write`; dry-run
resolves and displays the exact site and WLAN object without applying it.

Controller-managed UniFi APs also expose a local recovery surface over SSH.
The AP driver reads identity, adoption status, radio/SSID state, and associated
stations. Controller reassignment and reboot are mutations and require both
`--write` and an optional dry run first:

```sh
mycelium add 192.168.99.11 --driver unifi --user "$AP_USER" --password-env AP_PASS
mycelium call <ap-id> unifi.status
mycelium call <ap-id> wlan.list-ssids
mycelium call <ap-id> wlan.list-stations
mycelium call <ap-id> unifi.set-inform \
  --param url=http://192.168.99.20:8080/inform --write --dry-run
```

The saved inventory contains the environment-variable name, never the AP
password. UniFi network-wide configuration remains controller-owned; the AP
driver is for observation, recovery, and explicit adoption operations.

## Development

```sh
cargo check --workspace
cargo test --workspace
```

Small, focused pull requests are welcome. Please include tests for behavioral
changes and keep device mutations behind the existing plan/`--write` boundary.

## License

Licensed at your option under either the [Apache License, Version 2.0](LICENSE-APACHE)
or the [MIT license](LICENSE).
