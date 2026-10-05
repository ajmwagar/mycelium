# DNS Lua host adapters

These optional adapters use the existing bounded SSH command ABI. They do not
add HTTP networking or credential access to the Lua sandbox, and make no live
DNS changes during discovery. Copy the wanted file from
`crates/mycelium-plugins-lua/plugins/{nextdns,pihole}.lua` into
`$MYCELIUM_HOME/plugins/`, then restart the daemon. The selected target must have
the vendor CLI installed and its SSH credential binding configured. Driver names
are `lua:nextdns` and `lua:pihole`; explicit selection avoids a generic OS driver
winning recognition on the same host.

## NextDNS

The **NextDNS host/CLI adapter**, not a cloud-profile API driver, observes
`system.identify`, `system.health`, and `nextdns.profiles`. Native service status
does not prove successful DNS resolution. Only profile assignments are projected
from configuration; no raw configuration, query history or client inventory is
returned. Cloud deny/allow lists, analytics, profile writes and API-key handling
are unsupported. Profiles can contain subnet/MAC selectors: treat observations
as private inventory rather than public advertisements.

## Pi-hole

The adapter requires v6 identity and supports `dns.list-entries` and `dns.block`
for **explicit exact denylist entries only**. It does not claim gravity feeds,
regex rules, allowlist precedence, group assignments, DHCP or upstream settings.
Membership in a denylist does not prove every client will block that domain.

Mutation goes through the existing write gate/dry-run plan. Dynamic domains are
validated and passed as structured, shell-quoted arguments. An actual block is
followed by a fresh `pihole deny --list` read; missing membership, unexpected
format or incomplete list evidence fails loudly. A plan can independently verify
the same read-only capability with a membership predicate. There is no automatic
rollback/removal: a failed verification may follow a successful partial change,
so inspect the denylist before retrying or undoing it through the native CLI.

Pi-hole owns its CLI's v6 API authentication/session lifecycle. Mycelium uses only
the SSH credential reference and does not store Pi-hole passwords or session IDs.
Use a preauthorized noninteractive CLI environment: no password prompt, sudo
escalation or web-session fallback is injected by the plugin. Native CLI errors
and format changes stop execution. Human runbook: check `pihole version`, inspect
`pihole deny --list`, run `pihole deny <domain>`, then inspect membership again.

## Verification and references

`cargo check -p mycelium-plugins-lua --tests` then
`cargo test -p mycelium-plugins-lua --test dns_plugins` use recording transports;
they do not need credentials and do not contact a live DNS service.

Primary interfaces checked against [NextDNS command implementation](https://github.com/nextdns/nextdns/blob/master/main.go),
[NextDNS service status](https://github.com/nextdns/nextdns/blob/master/service.go),
[NextDNS configuration CLI](https://github.com/nextdns/nextdns/blob/master/config.go),
and [Pi-hole v6 exact-domain CLI](https://github.com/pi-hole/pi-hole/blob/master/advanced/Scripts/list.sh).
The textual Pi-hole parser is deliberately strict; a new output format requires
updated fixtures rather than silently treating an unknown response as an empty list.
