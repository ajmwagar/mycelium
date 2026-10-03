# Lua plugin boundary audit

This audit asks which existing Rust implementations should become bounded Lua
plugins. The goal is not to maximize Lua. Rust owns transports, credentials,
safety, typed topology, persistence, and protocol correctness; Lua owns small
vendor dialects that turn structured inputs into deterministic plans or facts.

## Decision rule

Move code to Lua when all of these are true:

1. The behavior is vendor- or product-specific rather than protocol-generic.
2. It can be expressed as a pure recognition, parsing, or command-planning
   function.
3. Rust can validate the inputs and outputs at a narrow typed boundary.
4. Lua does not need sockets, files, secrets, clocks, retries, or arbitrary
   process execution.
5. A malformed plugin cannot bypass dry-run, mutation risk, verification, or
   authorization gates.

Repeated code is not automatically plugin code. Security-sensitive escaping,
network type validation, transport lifecycle, and merge semantics should have
one shared Rust implementation.

## Inventory and recommendations

| Existing area | Recommendation | Reason |
|---|---|---|
| Advertisement vendor recognition | **Lua now** | Already a pure `ServiceAdvertisement -> DiscoveredDevice?` interface. Continue using it for protocol evidence such as ONVIF or vendor discovery frames once a Rust observer produces the generic advertisement. |
| UniFi AP over SSH | **First driver migration** | Model matching, `mca-cli-op info`, `iwconfig`, `wstalist`, `set-inform`, and reboot are a compact vendor command dialect. Rust should retain SSH, credentials, risk gates, output limits, and command execution. |
| SNMP enterprise/vendor classification | **Lua after a classifier ABI** | Enterprise OID and `sysDescr` classification changes independently of SNMP transport. Feed normalized system facts to a pure classifier; keep BER, SNMP GET/WALK/SET, standard MIB projections, limits, and write authorization in Rust. |
| Vendor-specific SNMP MIB projections | **Lua after a query-plan ABI** | A plugin can declare bounded OIDs and transform returned varbinds. Rust must validate OIDs, enforce row/query limits, perform transport, and own mutations. |
| EdgeOS/VyOS command dialect | **Hybrid later** | Command spelling and banner recognition are plugin-shaped, but DHCP/VLAN validation, normalized intent, transactional commit/save, verification, and topology observations are core infrastructure behavior. Lua may translate a validated intent into commands; it should not own the intent model. |
| NETGEAR FastPath | **Keep Rust** | Startup-config normalization, SNMP state, reconciliation, and VLAN invariants form one typed state machine. Moving its text parser to Lua would weaken validation without removing a meaningful duplicate. Vendor model aliases may become data or a classifier plugin. |
| Linux and Darwin observers | **Keep Rust** | They are platform providers producing typed interfaces, routes, neighbors, listeners, resources, and services. Their command strings differ, but their semantics and parsers are core topology inputs, not vendor extensions. |
| Redfish | **Keep protocol in Rust** | HTTP/TLS, authentication, link traversal, JSON bounds, action semantics, and session/error handling belong to a generic Redfish client. Product quirks may eventually be pure profiles, but the current SSH-only Lua host cannot safely implement them. |
| UniFi controller | **Keep HTTP/session layer in Rust** | Login cookies, TLS policy, credentials, pagination, retries, and API errors are transport concerns. Small response projections could be Lua later, but would provide little value before a generic bounded HTTP host exists. |
| Tailscale, DNS-SD, SSDP, STUN, WireGuard | **Keep Rust** | These are protocol implementations and shared observation providers. Lua should consume normalized facts, never parse security- or network-critical wire formats. |
| Firmware parsing and patching | **Keep Rust** | Binary bounds, integrity, deterministic patching, and hardware safety are not an embedded scripting boundary. |

## Repetition that should become shared Rust

The audit found several repeated implementation patterns, but moving them into
each Lua script would merely relocate the duplication:

- SSH target extraction, default ports, jump-host handling, connection timeout,
  command execution, and nonzero-exit conversion appear across EdgeOS, Linux,
  Darwin, and UniFi AP drivers.
- Stable slug generation is repeated across Darwin, Linux, EdgeOS, Redfish,
  SNMP, UniFi, and the Lua host.
- CIDR parsing appears in EdgeOS, Linux, daemon credential matching, and daemon
  RPC handling.
- String parameter extraction and shell quoting are reimplemented by multiple
  drivers.
- Capability declaration, dry-run planning, mutation gating, and verification
  are repeated structurally across native drivers and plugins.

These should converge on Rust-owned helpers or typed contracts. In particular,
Lua should never hand-roll shell escaping. A plugin should emit an argument
vector or call a host-owned quoting primitive, and Rust should render the final
command for transports that only accept shell text.

## Small host ABI additions

The present driver ABI can plan SSH commands and parse their stdout, but it
cannot safely replace the UniFi AP driver yet. Four deliberately small
extensions unlock that migration without turning Lua into an orchestration
runtime:

1. **Declarative probe** — `probe(target) -> command plan`, followed by
   `recognize(outputs) -> identity?`. Today `match(target)` sees only address
   and port, so it cannot distinguish two products on SSH port 22.
2. **Structured command arguments** — accept `{ program, args }` in addition to
   raw command text. The Rust transport owns validation and shell rendering.
3. **Bounded output decoders** — host decoders such as `json`, `lines`, and
   `key_value` run before Lua. This avoids embedding another JSON parser and
   keeps size/depth limits in Rust.
4. **Typed observation validation** — retain the existing
   `topology.observe` projection, but validate origin assignment in Rust and
   reject plugin-supplied authority or credentials.

Do not add generic HTTP, filesystem, clock, background-task, or unrestricted
process APIs merely to migrate a driver. Introduce a bounded protocol host only
when at least two real drivers share the need.

## Recommended sequence

Status: the bounded probe/decoder ABI and built-in UniFi AP Lua driver now
replace the native AP implementation; the HTTP controller driver remains Rust.
Shared Rust helper consolidation continues independently.

1. Extract shared Rust helpers for stable IDs, CIDRs, and SSH command execution.
2. Add declarative probe and bounded decoders to the Lua driver ABI, with
   negative tests for command injection, oversized output, malformed identity,
   and mutation bypass.
3. Port the UniFi AP SSH driver to a built-in Lua plugin and verify identity,
   capability, dry-run, structured-argument, and decoded-result parity.
4. Remove the native UniFi AP implementation after parity; keep the controller
   driver in Rust. **Completed.**
5. Add a pure SNMP classification/profile ABI over normalized Rust varbinds.
6. Revisit EdgeOS only at the normalized-intent-to-command boundary. Do not
   move its network model or reconciliation state machine into Lua.

The immediate payoff is not fewer Rust files by itself. It is one durable Rust
host with small replaceable product dialects, while topology and mutation
safety remain deterministic and testable.
