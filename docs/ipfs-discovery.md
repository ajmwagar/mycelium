# IPFS discovery

The existing Linux observer selects at most four already-observed loopback TCP
listeners. Default RPC ports 5001/5002 are candidates, not identity evidence;
custom ports require an observed `ipfs` or `kubo` process. It never scans remote
administrative APIs or enables Kubo access.

Rust retains the bounded HTTP transport: only POST `/api/v0/version`, then
`/api/v0/id` after successful version recognition. Each request has a two-second
deadline, no redirects and no proxy use. Responses are capped at 4 KiB for
version and 16 KiB for identity. No config, pins, keys, content or swarm peers
are queried or modified. Identity failures become scan warnings without
discarding already-verified version evidence.

`crates/mycelium-plugins-lua/plugins/kubo.lua` maps these responses in the
existing bounded Lua service-provider host. It exports only version, public
peer ID and at most 32 deduplicated advertised multiaddress strings. These are
observed names, not verified routes; the host does not derive IPs or gateway
URLs from them. Public-key material and arbitrary extra JSON fields are omitted.

The original `ipfs-rpc` listener observation carries the non-secret facts in
optional generic `ServiceRecord.attributes`, using the existing topology and
gossip path. Older saved records without this field remain readable. Service
projection keeps `kind=ipfs`, `role=rpc`, `administrative=true` and
`endpoint_scope=host-local`; it exports no routable endpoint. Deploy updated
observers and consumers before depending on these additional fields.

## Gateway names

Only an application-owned `ipfs-gateway` lease may nominate a browser entrance.
A Kubo RPC observation, process, port 8080 or `/p2p/<id>` advertisement does not.
Use the existing shared owner-catalog format rather than another registry.

The optional `plugins/ipfs_dns.lua` naming policy maps `ipfs-gateway` to `ipfs`.
Install the reviewed file under an administrator-owned absolute path and add
that path to resolver `service_alias_plugins`. The generic resolver still
requires a fresh owner lease, a literal HTTPS endpoint matching the owner's
fresh site-scoped peer address, and explicit policy for any root index alias.
HTTP-only gateways are not promoted by this secure browser alias path.

Review `mycelium-dns-resolver plan --config ABSOLUTE_SETTINGS_PATH` before using
the existing write-gated apply workflow. This plugin does not enable a gateway,
change a firewall, issue TLS certificates, grant access or publish RPC names.
IPFS content CIDs remain content identities, independent of host names and ACLs.

## Manual verification

1. On the observer host inspect `ss -H -lntup` for loopback RPC listeners.
2. POST the version endpoint with `curl -q --noproxy '*' --proto '=http'
   --connect-timeout 1 --max-time 2 --max-filesize 4096 -fsS -X POST`, using only
   an observed loopback address and port. Then probe `/api/v0/id` with the same
   restrictions and a 16384-byte limit. Do not probe arbitrary LAN APIs.
3. With the updated observer, run the existing Mycelium scan and inspect
   `mycelium services --kind ipfs --json`. Check peer ID and advertised address
   facts, original timestamps, and absence of browser/RPC endpoints.
4. If a gateway is intentionally advertised, inspect its owner lease and the
   DNS plan separately. Resolve its approved name, then verify HTTPS with the
   correct CA and application authorization. Do not use `curl -k`.

Titan and Agora were inspected read-only during this slice. Both reported Kubo
0.43.1 on loopback port 5002 and distinct peer IDs. Each advertised only its
`/p2p/<id>` address, which supplies no dialable host or browser gateway.
