# Site DNS and namespace ownership

Mycelium owns mesh/site naming; a workload runtime owns its members. Shroud's
`.shroud.svc` namespace stays resolver-backed by Shroud, including stable service
identity, named ports, healthy promoted revisions and replicas. Mycelium must
not flatten those members into a second registry or revision-IP hosts file.

This is the ownership boundary, not a claim that Shroud's serving-alias rollout
is finished. The existing `shared-infra-a7l` audit distinguishes prepared
reservation names from promoted serving aliases (`shared-infra-a7l.1`). It also
requires an authoritative local-zone guard before host attachment. A successful
DNS query alone does not establish workload readiness or rollout completion.

`mycelium dns zone` retains the existing topology/site-route-derived hosts view.
`mycelium dns plan` adds a bounded, site-scoped policy projection with explicit
namespace delegation. It is read-only: there is no resolver apply driver yet.
JSON includes `apply_supported: false` and required post-change checks.

## Plan

Prepare a private delegation file. This example uses documentation addresses;
replace them with a resolver verified reachable from the intended DNS host:

```json
[
  {
    "zone": "shroud.svc",
    "site": "lab",
    "owner": "shroud",
    "server": "192.0.2.53",
    "port": 53
  }
]
```

```sh
mycelium dns plan --site lab --suffix mesh.example.net \
  --delegations ./dns-delegations.json --json
mycelium dns plan --site lab --suffix mesh.example.net \
  --delegations ./dns-delegations.json --dnsmasq
```

Site records are derived through the existing topology and WireGuard-binding
view, not a new peer database. The delegation file stores namespace ownership
intent, never member addresses, credentials or private transport keys. `owner`
is descriptive configuration, not an authentication or delegation grant.

The dnsmasq fragment contains exact `host-record` entries, a local-zone guard
for Mycelium names, and domain-scoped upstream `server` entries. It does not
alter listener bindings, DHCP, uplink resolvers, certificates or access grants.
Separate sites should use separate resolver views. Delegated zones cannot take
over the Mycelium namespace, overlap each other or receive Mycelium records.
Missing services do not remove the owner delegation. Duplicate/conflicting
ownership, invalid names, `.local`, wildcard/injection syntax and ambiguous
resolver addresses fail before producing a plan. Delegation port is explicit.

## Application boundary

Unibus can use the existing provider-neutral service catalog to discover
application endpoints. Iroh endpoint IDs and authenticated key bindings remain
transport metadata; they are not encoded as an IP DNS record or an ACL. DNS
resolution alone does not prove a route, authenticate a peer, or grant access.

User-facing HTTP names should point at stable ingress, not ephemeral Shroud
revision IPs. Palisade's optional intranet projection describes approved frontend
names separately from accepted backend-route membership; it is not a replica
registry. The projections do not automatically start workloads or publish every
observed listener.

## Resolver activation gate

Do not paste the fragment into a live router as an automatic fallback. Persistent
activation requires an owning driver with an explicit write gate, ownership
check, rollback and read-only verification. This slice does not provide that
contract, edit macOS/Linux resolver settings, or deploy a fungOS DNS daemon.

Qualification must check, from the actual resolver host and a LAN client:

1. Mycelium names resolve to the reviewed site addresses.
2. Shroud names resolve through Shroud's owner resolver.
3. A nonexistent Shroud name receives the owner's negative answer without a
   forwarding loop or public-uplink fallback.
4. Unrelated public queries still use the previous uplink DNS.
5. Workload replacement changes owner answers without copying membership.
6. Resolver restart/reboot preserves the intended namespace bindings.

The existing shared-infra Shroud host-DNS attachment verifies bridge and local
zone guards before configuring only the Shroud routing domain. Reuse that owner
integration; do not make Mycelium seize its bridge or default DNS settings.

Policy checks: `cargo check -p mycelium-dns-policy`, then
`cargo test -p mycelium-dns-policy`. CLI integration:
`cargo check -p mycelium-cli --tests`, then focused CLI DNS tests.
