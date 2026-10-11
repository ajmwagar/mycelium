# Shroud service discovery

`mycelium services discover --plugin /path/to/shroud.lua --socket /var/lib/shroud/control.sock --node OWNER_NODE_ID`
reads Shroud's control socket using only its fixed `discover` operation and prints
an existing-format service catalog. It does not start workloads, change DNS,
publish leases, or grant access. Socket permission is required; do not expose the
control socket to browsers or grant it to discovery users.

The projection includes only running, ready HTTP/HTTPS services over TCP.
Replicas collapse onto stable service-name/port identities and `.shroud.svc`
endpoints. VM addresses, revision IDs, runtime metadata and proposed Palisade
routes are not exported. Conflicting aliases fail closed. Observations expire
after 120 seconds; an unsuccessful read must never renew old observations.

Shroud owns this namespace. A ready observation does not prove that a client's
DNS, routing or application authorization works. Mycelium's existing explicit
DNS delegation can forward the namespace without copying Shroud's records.

Automatic owner-lease publication and the separately authorized browser service
view are not yet wired. This command is the bounded discovery adapter for that
integration, not a live registry or deployment controller.

## Extension boundary

Shroud-specific requests, health filtering, aliases and `.shroud.svc` naming
live in `crates/mycelium-plugins-lua/plugins/shroud.lua`, not a Rust adapter.
The generic host accepts `service_provider = { name, request, project }`.
`project(response, context)` receives bounded decoded JSON plus the host's node
identity, observation time, schema version and explicit empty array. It returns
the existing service catalog, validated again by the shared owner-lease parser.

Providers have no files, sockets, clocks or process execution. Source, memory,
instruction count, JSON depth, input and output sizes are bounded. Invalid owner
identity, credential-bearing URLs, oversized or fabricated leases fail closed.
Loading a provider does not delegate a DNS zone or grant application access.
The existing DNS policy validates operator-selected namespace delegations;
Shroud continues to answer its own records.

Only load reviewed provider code: the declared JSON request is executable
configuration, and a generic socket cannot prove arbitrary vendor operations
are read-only. The supplied Shroud provider declares only `discover` with
`includeUnready=false`. Socket permissions remain the access boundary. No
browser accepts uploaded plugins or access to the control socket.
