# Mycelium scope audit

Mycelium is the infrastructure nervous system: it observes, correlates, retains
signed facts, resolves access paths, distributes its own trusted updates, and
explains narrow management plans. It is not the service supervisor, message
bus, identity provider, package manager, SIEM, DNS server, or firmware lab.

## Unix boundary

Features should follow these rules:

1. One owner per capability. Call Bifrost, Fabd, Unibus, OpenTofu, or a system
   tool rather than reproducing it.
2. Mechanism stays separate from policy. Drivers expose bounded mechanisms;
   explicit intents and external consumers choose policy.
3. JSON is the stable composition interface. Human output is a projection.
4. Observations prove availability, never authority.
5. Read commands compose without a daemon mutation. Writes require explicit
   plan/apply semantics and produce receipts.
6. Providers and transports are replaceable. No consumer imports Mycelium's
   database or gossip internals.
7. The daemon retains signed facts and health; it does not run open-ended
   workflows.

## Feature disposition

| Surface | Disposition | Boundary |
|---|---|---|
| peers, scan, discovery, topology, map, annotate | **Core** | Observe and correlate identity, attachment, sites, services, and movement. |
| resources, hardware | **Core** | Publish provider-neutral capabilities and expiring attachments; never grant use authority. |
| SSH, SCP, tunnel, console | **Core access mechanism** | Resolve paths and invoke standard tools. Do not replace SSH or terminal protocols. |
| enrollment, pairing, authority, access records, renewal | **Core trust** | Peer/access identity, short-lived credentials, delegation, and revocation are necessary for a decentralized nervous system. |
| OIDC verify/join | **Adapter** | Convert an external IdP assertion into a bounded Mycelium claim. |
| OIDC gateway | **Extract/freeze** | Callback UI, provider sessions, and account lifecycle belong to an auth service. Keep compatibility while moving hosting behind an adapter binary. |
| self-update, release gossip, artifact cache | **Core updates** | Mycelium must update itself safely and share verified content by digest. |
| packages/software policy/reconcile/activate | **Freeze at delivery** | Keep signed artifact delivery and status. Fabd builds; Bifrost/system supervisors activate, drain, restart, and roll back services. |
| targets, drivers, describe, call, executions | **Core management mechanism** | Narrow capabilities with explicit risk, plans, validation, and receipts. |
| network allocations, drift, plan | **Core recommendation** | Derive intent and explain drift from topology. |
| network apply, DHCP/VLAN operations | **Driver adapter** | Translate an explicit plan to EdgeOS/UniFi/Linux mechanisms; do not host DHCP/DNS or own a second state engine. |
| WireGuard, DERP/NERP/STUN, Tailscale | **Core transport observation/planning** | Describe reachability, NAT, sites, and paths. External/system drivers own persistent route and firewall reconciliation. |
| DNS zone | **Projection adapter** | Emit records from topology. Never become an authoritative DNS server. |
| health, CVE, STIG findings, security events | **Core observation** | Deterministic local checks and signed facts fit the nervous-system role. |
| Loki/MQTT/JSONL sinks | **Export adapters** | Ship normalized events; do not become a SIEM datastore or message bus. |
| security inspection placement | **Recommendation** | Identify useful sensor placement. Packet capture and IDS execution remain external. |
| security remediation apply/verify | **Extract/freeze** | Keep generated findings and plans; broad host remediation belongs to Ansible/Bifrost or an explicit compliance tool. |
| PXE boot-path and NBDE plans | **Recommendation adapters** | Explain reachability and emit configuration. DHCP, TFTP, image building, Tang, and Clevis remain external tools. |
| fleet status | **Core projection** | A read-only view over peer facts. |
| fleet exec | **Thin convenience** | Must remain a deterministic loop over `mycelium exec`, not an orchestration engine. |
| skills install/sync | **Extract/plugin** | Useful packaging convenience, but unrelated to infrastructure observation and access. |
| Lua plugins | **Keep bounded** | Discovery/driver extensions through narrow host APIs only; no general workflow runtime. |
| firmware inventory/update eligibility | **Driver adapter** | Observe versions and invoke explicit vendor-supported operations. |
| replacement firmware, emulators, reversal, payloads | **Separate workspace/project** | Research artifacts must not be default dependencies of the Mycelium product. |

## Concrete tightening

1. Add workspace `default-members` containing the CLI, daemon, core protocols,
   discovery providers, and production drivers. Firmware research and MIDI
   experiments remain buildable explicitly but leave the default product gate.
2. Mark command families in help and documentation as `core`, `adapter`, or
   `experimental`; experimental persistence formats receive no compatibility
   promise.
3. Freeze new behavior in `software activate/reconcile`; evolve a handoff
   contract to Bifrost instead.
4. Split hosted OIDC gateway and skill installation into optional adapter
   binaries without changing their provider-neutral contracts.
5. Make security remediation emit/export plans by default; execution should be
   delegated to a named external mechanism.
6. Keep network mutation behind driver capabilities and execution receipts.
   Mycelium may calculate the plan but must not grow a second desired-state
   engine.
7. Publish neutral topology/resource/security snapshots to Unibus through an
   adapter. Unibus grants remain the authority for message flow.

## Admission test

A proposed core feature must materially improve at least one of:

- observation,
- identity correlation,
- topology and movement,
- access and revocation,
- self-update integrity,
- reachability/path understanding,
- health or security posture,
- explainable narrow driver planning.

If its primary purpose is running applications, routing application messages,
building binaries, authenticating human accounts, hosting infrastructure
services, or storing long-lived analytics, Mycelium should expose facts or call
the owning tool instead.
