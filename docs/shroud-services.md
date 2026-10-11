# Shroud service discovery

`mycelium services shroud --socket /var/lib/shroud/control.sock --node OWNER_NODE_ID`
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
view are not yet wired. This command is the bounded read-only adapter for that
integration, not a live registry or deployment controller.
