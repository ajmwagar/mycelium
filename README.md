# mycelium
A sensing framework for your networks. Home, Cloud, anywhere.

Mesh / AI control over home IoT devices and networkign applicances.

No more Port Forwarding, Manual VLAN tagging, or firewall rules.

Secure by default, and only with justification.

# Architechture

1. Rust Core / Lua Plugins

2. Integrate / Interop / Don't replace unless nessecary

3. Anti-Abondonware, generalize the common, implement everywhere.

4. Secure by default. Intelligent. Restraint is good.

5. Multi-LAN/WAN

# UX

A control plane / CLI for your home network.

Integrate across, brands, support iPMi, bare metal integration across the board.

Network Topology Mapping / Viewing

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

SEIM (FIPS Compliant Syslogs)?

## Initial Targets

EdgeRunner Routers, ER-10X EdgeRunner Edge?

wifi management (guest networks)

NETGEAR Switch

Dell iPMIE

Ubiquti APs.

Pi-Hole?

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
mycelium add titan --driver linux --user avery
mycelium scan
```

The Linux driver runs a fixed, read-only `iproute2` probe over SSH. It uses
OpenSSH configuration and agent credentials when no password or key is given.
Each observer hostname is also its site identity, so overlapping private
networks are stored separately (`pris/192.168.1.0/24` and
`titan/192.168.1.0/24`) instead of producing false address conflicts.

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

# Initial Features

DNS Management, DHCP Management, VLAN Management (rules, etc.)

SEIM / Intrusion Management / Exfiltration monitoring.
