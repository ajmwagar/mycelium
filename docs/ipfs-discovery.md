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

## First private HTTPS gateway

Agora now serves a dedicated tailnet-only content entrance:
`https://agora-one.tail5ba253.ts.net:8446/ipfs/CID`.
This deployment reuses existing Tailscale Serve TLS; it does not require
Tailscale in the Mycelium contract or expose a public gateway. Tailnet policy,
not Mycelium viewer grants, currently controls who can reach this entrance.
No `ipfs.myc` alias or owner lease has been activated.

The reviewed configuration is `examples/ipfs-gateway/nginx.conf`. A dedicated
unprivileged, read-only nginx container shares the existing private Kubo Docker
network and publishes only `127.0.0.1:8789`. It permits GET/HEAD under `/ipfs/`,
blocks all other paths, strips cookies and authorization, disables scripts in
content, and forwards to Kubo's content port 8080, never RPC port 5001.
This is a path gateway, not an arbitrary application-hosting origin.
Authorized clients can retrieve content available through this Kubo node;
there is no per-CID ACL or local-pins-only restriction.

Deployment runbook (Agora-specific existing network/container names):

1. Copy the configuration to `/etc/mycelium/ipfs-gateway/nginx.conf`, root-owned.
2. Validate with `nginx -t` using the same image and mounted configuration.
3. Start the container:

   ```sh
   sudo docker run -d --name mycelium-ipfs-gateway --restart unless-stopped \
     --network unibus-ipfs-private_default --read-only --cap-drop ALL \
     --security-opt no-new-privileges --user 101:101 \
     --tmpfs /tmp:rw,noexec,nosuid,size=16m -p 127.0.0.1:8789:8080 \
     -v /etc/mycelium/ipfs-gateway/nginx.conf:/etc/nginx/nginx.conf:ro \
     --entrypoint nginx \
     nginx@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94 \
     -g 'daemon off;'
   sudo tailscale serve --bg --https=8446 --yes http://127.0.0.1:8789
   ```

4. Add the non-secret `examples/ipfs-gateway/welcome.txt` document using Kubo's
   local `ipfs add --cid-version=1 -Q` CLI. This pins the sample; no existing
   pins or Kubo settings are changed. Verified CID:
   `bafkreihnomwdkaytc4h53x7fuks253yxfobmjsims4yvtzvnjrmrylpyyy`.
   The earlier sample CID remains pinned; no existing content was deleted.
5. Verify HTTPS without `-k`: GET and HEAD on that CID return 200; GET
   `/api/v0/version` returns 404; POST on the content path returns 405.
   Compare downloaded document bytes with the source file. Confirm prior
   Serve routes are still present and only loopback port 8789 is published.

Rollback without touching other HTTPS routes or Kubo:
`sudo tailscale serve --https=8446 off`, then
`sudo docker stop mycelium-ipfs-gateway`. These preserve the container,
configuration and pinned sample for inspection/recovery. Re-enable with
`docker start` and the Serve command above. Restart policies are configured;
a full host reboot has not been tested.

## CID hostnames on Mycelium DNS

Neo now resolves `CID.ipfs.myc` to Agora's reachable LAN address and validates
HTTPS against the already-trusted Mycelium web CA. The dedicated gateway listens
on `192.168.2.67:443`, not the Tailscale HTTPS listener. It uses
`examples/ipfs-gateway/subdomain.conf` and the same restricted container options
as above, but maps host CID plus request path into Kubo's `/ipfs/CID` content
path. Only canonical lowercase base32 labels up to 63 characters are accepted;
Kubo validates the CID itself. CIDv0 names must first be converted to CIDv1
base32. IPNS and nested DNSLink names are not implemented.

Namespace ownership is explicit operator policy, separate from application Lua
aliases and discovery. The generic resolver's `namespace_owners` map selects
the authorized peer, not a configured IP or a hardcoded IPFS implementation:

```json
"namespace_owners": {
  "ipfs.myc": "87a7134985e83ac40cbb0e3e3d4d889093f9c8564db4f3ec5aab28eeebe3a67f"
}
```

Put this map inside `resolver`. Addresses derive only from that peer's fresh
site-scoped records and reviewed reachable prefixes; absent owner evidence
withdraws the answer. Owners may be in another admitted mesh site: the resolver
unions the existing validated site plans before namespace ownership and
collision checks. Unadmitted raw observations cannot supply an owner address;
conflicting canonical names across admitted sites fail closed. This is generic
namespace policy, not an IPFS-specific address table; no substitute gateway is
chosen when the owner disappears. Configured child zones
cannot overlap delegations, other child owners or exact peer/service records.
The `.myc` local guard prevents public DNS fallback. This is intentional
namespace provisioning, not an inference that any detected Kubo is a gateway.
Lua still owns application alias naming; neither plugin nor observation may
grant a namespace. DNS proves neither service health nor content authorization.

Issue the leaf using a peer-signed CSR and explicit issuer option
`mycelium web-ca issue ... --namespace ipfs.myc --write`. Keep the generated
HTTPS key on Agora and the CA key only on the issuer. The wildcard leaf expires
after seven days and requires the documented manual renewal; unattended
gateway renewal is not implemented. The nginx container must restart after
atomically replacing a file-mounted certificate/configuration, so Docker
remounts the new inode. Validate configuration first.

Neo settings are private at `~/.mycelium/dns/neo-ipfs.json`. The existing
supplemental `.myc` OS resolver was reused; default DNS and DHCP are unchanged.
DNS backup executable is `~/.mycelium/dns/mycelium-dns-resolver.pre-ipfs-namespace`.
Rollback the DNS policy by applying the previous `neo.json` through that backup;
stop `mycelium-ipfs-subdomain` to withdraw the new LAN HTTPS entrance. The
separate tailnet gateway stays available. No full reboot qualification yet.

Verified without `--resolve`, `--cacert` or `-k` on Neo:
`https://bafkreihnomwdkaytc4h53x7fuks253yxfobmjsims4yvtzvnjrmrylpyyy.ipfs.myc/`.
Downloaded bytes match the pinned document; POST returns 405, the admin API
path returns 404, and unrelated public DNS continues working. This LAN
entrance has no Mycelium viewer ACL or per-CID authorization; any client with
network access can retrieve available content. Do not put secrets in IPFS
without a separate encryption/access design.

## Actual PDF verification

The welcome text above is not a PDF. A one-page PDF example is authored in
`examples/ipfs-gateway/welcome.typ`; with Typst installed, render it using:

```sh
mkdir -p output/pdf
typst compile examples/ipfs-gateway/welcome.typ output/pdf/mycelium-ipfs-welcome.pdf
```

The visually inspected and pinned PDF is available at:
`https://bafkreihva3evq42zjijp7k6jfjiyynifc2inioz4xnnwrtyly3gm32vcha.ipfs.myc/`.
Verified through normal Neo DNS and trusted HTTPS: GET returns 200 with
`Content-Type: application/pdf`, all 53,271 downloaded bytes match the local
artifact, and `Range: bytes=0-4` returns 206 with `%PDF-`. The PDF has one A4
page, no JavaScript or forms, and was rendered to PNG for layout inspection.
No browser automation was available; native Safari's PDF presentation was not
separately verified. Rerendering can change the CID (including PDF metadata).
