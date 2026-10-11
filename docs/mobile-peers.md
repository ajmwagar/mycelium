# Mobile peers and sites

A peer's Ed25519 public key is its stable node identity. Moving a laptop or
phone between networks must not reenroll it, rotate transport bindings, or
change its access roles. Reachability is not authorization.

`PeerHello.site` currently denotes the administrative/enrollment site selected
by `MYCELIUM_SITE`. It is not evidence of physical presence. Site-based
software policy and the discovery index continue to use that administrative
grouping. Changing an IP address does not change this field.

The daemon samples and signs a complete interface snapshot every 60 seconds,
using the existing health cadence. A new snapshot replaces old addresses and
can describe Ethernet, Wi-Fi and VPN interfaces simultaneously. An empty
successful sample removes previous attachments. A failed probe is reported
and does not renew a false empty observation. No additional discovery scan or
network mutation is performed.

## Remaining attachment contract

Current physical placement must be derived separately for each interface from
fresh network evidence, not from the enrollment site, a hostname, a matching
RFC1918 prefix alone, or Tailscale/Iroh reachability. A peer may have multiple
LAN attachments, or unknown/ambiguous placement. A VPN address is a transport
path, not proof that the device is physically at either endpoint's site.

Before exposing current-site views or changing DNS and routing selection, the
shared attachment projection needs an explicit evidence boundary: which
gateway/segment observations identify a site, their provenance and expiry,
and how competing observations remain ambiguous. It should reuse topology
segments and signed observations rather than create another registry.

Existing consumers still need tightening: topology currently stamps peer
interfaces and observed endpoints with the administrative site, and discovery
index freshness uses the latest event of any kind. Health activity must not
refresh the age of an old interface snapshot after probe failure. Address
selection and LAN DNS must consume attachment freshness, while stable names,
ownership and ACLs continue to follow peer identity.
