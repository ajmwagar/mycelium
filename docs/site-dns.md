# Site DNS and namespace ownership

## Lightweight refresh

The managed resolver queries `mycelium peers --names-only --json`, a bounded
projection of signed peer identities, interface addresses and observation times.
It shares latest-identity selection with the site index, but does not serialize
health, processes, hardware or transport diagnostics. The ordinary `peers`
command retains its full view. Resolver and CLI/daemon upgrades must land
together: an older daemon rejects the new request rather than silently falling
back to an expensive inventory read.

## Local index entrances

Alongside opt-in `service_aliases`, an optional `service_index_peers` map selects
one stable peer identity per service kind for `mycelium.myc` and `unibus.myc`.
The same fresh owner leases and reachable address checks used for per-host aliases
apply. A root alias is emitted only for the selected owner and configured service
kind, never an arbitrary available peer. Changing that selector invalidates
retained records; expiry withdraws the alias instead of silently choosing a new
gateway. The resolver suffix is configurable. DNS still does not choose ports,
publish a page, provision credentials, or grant access.

Both the server certificate and browser trust must cover the new entrance name.
Without owned port-443 ingress, use the advertised HTTPS port in the URL.

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
# Optional local resolver

`mycelium dns resolver` manages an optional dnsmasq companion, not another DNS
server implementation. Embedded nodes can leave it off and use LAN DNS. Modes:

| Mode | Configuration | Activation in this slice |
| --- | --- | --- |
| `off` | No resolver process | macOS stops the owned LaunchAgent |
| `localhost-only` | Explicit loopback listeners | macOS user LaunchAgent plus optional suffix-only OS routing |
| `lan-serving` | Explicit interface addresses | Plan only; verified client-network firewall policy is required before activation |

The companion also builds as `mycelium-dns-resolver`; it exposes the same actions
without requiring an installed CLI upgrade. Linux persistent activation remains
unsupported. This is not DHCP advertisement or a change to default DNS.

Store configuration outside the checkout, for example `~/.mycelium/dns/settings.json`:

```json
{
  "resolver": {
    "mode": "localhost-only",
    "site": "lab",
    "suffix": "myc",
    "listen": ["127.0.0.1:1053"],
    "upstreams": ["1.1.1.1:53"],
    "delegations": []
  },
  "dnsmasq": "/opt/homebrew/sbin/dnsmasq",
  "mycelium": "/Users/you/.local/bin/mycelium",
  "reachable_prefixes": ["192.0.2.0/24"],
  "refresh_seconds": 30,
  "expiry_seconds": 300
}
```

Binary paths must be absolute. Reachable prefixes are an explicit publication
scope, not a claim that an IP is routable. Start with the attached LAN; do not
publish every remote private address. Records derive from the authenticated
daemon's `peers --json`, filtered by site and freshness. Names are
`hostname.site.suffix`; live competing owners fail closed. Device annotations,
non-peer discovery is not included in this adapter.

## Optional daemon-page service names

`additional_sites` in dnsmasq settings optionally admits explicitly reviewed
remote sites from authenticated peer observations. The default remains local-only.
Names retain each peer's observed site; this is not a site-alias or rename API.
Reachable-address prefixes and freshness checks still apply. Changing the list
invalidates retained policy state. Delegated namespaces cannot overlap these
locally projected site namespaces. Never add a guessed site or remote private
prefix merely to make a viewer link appear to work.

Service aliases are default-off. Add a `service_aliases` map to resolver settings:

```json
"service_aliases": {
  "unibus-viewer": "unibus",
  "mycelium-host-web": "mycelium"
}
```

Alternatively, load a reviewed application naming policy:

```json
"service_alias_plugins": [
  "/usr/local/share/mycelium/dns-policies/unibus_dns.lua"
]
```

The supplied policy is `crates/mycelium-plugins-lua/plugins/unibus_dns.lua`.
Install it as a non-writable file owned by the resolver administrator. It maps
`unibus-viewer` to `unibus`; Unibus already publishes the shared owner leases,
so no new Unibus scraper, registry or DNS server is involved. Explicit maps
remain supported. Maps and plugins may agree, but conflicting mappings fail
closed. Loading a plugin does not select an index owner: `service_index_peers`
remains explicit operator policy.

The small Lua interface is `dns_policy.aliases(context) -> {kind = label}`.
Context contains the configured site and suffix, not credentials or inventory.
Rust bounds source, memory, instructions and output, then validates the labels,
owner provenance, lease freshness, site addresses and namespace ownership.
Plugins cannot return records, IPs, ports, ACLs or DNS delegation grants. DNS
protocol handling and the existing plan/apply driver remain generic Rust.

Use `mycelium-dns-resolver plan --config ABSOLUTE_SETTINGS_PATH` to inspect the
result before applying through the existing write-gated workflow. Absolute
plugin paths and existing filesystem permissions are required. Invalid or
missing policies fail visibly; they do not fall back to hardcoded names.
Each refresh resolves one policy snapshot. Retained records are bound to its
effective mappings; changing a mapping invalidates the old snapshot, without
renewing its leases. A failing candidate after a policy change cannot restore
the previous naming policy. No default DNS or DHCP changes are implied.

Labels must be unique canonical single DNS labels. The resolver reads the
existing `mycelium services --json` catalog, never scans ports itself. Only
fresh `mycelium-application-owner-lease` entries with matching node provenance
qualify. Their literal HTTPS endpoint must match a fresh reachable peer address
in this resolver's site. Names are `SERVICE.HOST.SITE.SUFFIX`, for example
`unibus.neo.wagar-house.myc` and `mycelium.neo.wagar-house.myc`.

Addresses outside that owner's peer evidence, loopback, scanned services,
expired leases, hostname endpoints and credential/path-bearing URLs are not
promoted. Competing entrances using different ports for the same name/address
fail closed. Retained snapshots expire no later than the earliest included
service lease or peer observation; changing alias policy invalidates them.
Failure to read the service catalog retains only the already-validated snapshot
until its original expiry, not a newly synthesized availability claim.

DNS does not carry ports or grant access. Use the port advertised in the service
catalog and a certificate with this name's DNS SAN. No port 443 proxy, certificate,
Iroh route, site-wide gateway selection, or automatic resolver activation is
installed here. Host pages and Unibus continue to enforce their own grants.

`.myc` is configurable private naming, not a registered/reserved public TLD.
Future public-name collision is possible. Use an owned subdomain or a reserved
private namespace if that risk is unacceptable. Unknown `.myc` names return a
local negative response rather than being forwarded. Public HTTPS certificates
are not supplied by local DNS.

Manual runbook (replace paths for your installation):

```sh
cargo check -p mycelium-driver-dnsmasq --tests --locked
cargo test -p mycelium-dns-policy -p mycelium-driver-dnsmasq --locked
cargo build -p mycelium-driver-dnsmasq --bin mycelium-dns-resolver --locked
# Install the companion in a stable location before creating its LaunchAgent.
install -m 755 target/debug/mycelium-dns-resolver "$HOME/.mycelium/bin/mycelium-dns-resolver"
export PATH="$HOME/.mycelium/bin:$PATH"
mycelium-dns-resolver plan --config "$HOME/.mycelium/dns/settings.json"
mycelium-dns-resolver apply --config "$HOME/.mycelium/dns/settings.json" --dry-run
mycelium-dns-resolver apply --config "$HOME/.mycelium/dns/settings.json" --write
mycelium-dns-resolver status --config "$HOME/.mycelium/dns/settings.json"
```

Activation validates dnsmasq syntax and available UDP/TCP listeners, creates
`~/Library/LaunchAgents/dev.fpl.mycelium-dns.plist`, then queries an expected
record's actual address. Failed startup restores the previous owned LaunchAgent
and its stored settings. Only this agent is managed, not Homebrew's global DNS
service. LaunchAgent persistence is across logins; it does not serve while the
user is logged out.

Once the direct listener works, install the macOS supplemental resolver with
administrator authorization:

```sh
sudo "$HOME/.mycelium/bin/mycelium-dns-resolver" system-install \
  --config "$HOME/.mycelium/dns/settings.json" --write
scutil --dns
dscacheutil -q host -a name hostname.lab.myc
```

Only `/etc/resolver/SUFFIX` is written; unowned existing files and symlinks are
refused. Check that normal internet DNS and existing VPN DNS still work. Browsers
with independently configured secure DNS may bypass the OS resolver.

The supervisor refreshes at the configured interval, validates a candidate
before replacing it, verifies the replacement, and restores the previous config
on failed activation. Observation failure is logged; retained records are
withdrawn at their observed expiry. An unexpired, policy-checked snapshot can
also survive a supervisor restart while discovery is unavailable. It shuts down its own dnsmasq child on
SIGTERM. No DHCP, TFTP or router advertisement is enabled.

Rollback OS integration first, then stop the companion:

```sh
sudo "$HOME/.mycelium/bin/mycelium-dns-resolver" system-remove \
  --config "$HOME/.mycelium/dns/settings.json" --write
```

Change `resolver.mode` to `off` in the private settings and run `apply --write`.
Off does not silently delete privileged namespace files; removal is an explicit
separate operation. DHCP option 6, LAN firewall enforcement and Linux service
activation remain follow-up work. `dns plan` remains a separate read-only
site projection, not evidence that a resolver has been activated.
