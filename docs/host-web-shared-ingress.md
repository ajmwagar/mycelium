# Host viewers sharing HTTPS with IPFS

Verified deployment, 2026-10-11: Titan and Agora use the existing embedded
Mycelium host viewer, not a telemetry collector. Their signed site identities
remain `titan` and `wagar-house` respectively.

## Ownership and routes

- `https://titan.titan.myc`: the systemd socket on `100.83.7.116:443`
  forwards TLS unchanged to the viewer on that host's `100.83.7.116:8443`.
- `https://agora-one.wagar-house.myc`: Agora's existing IPFS NGINX container
  publishes `192.168.2.67:443`. Its stream layer selects Mycelium's own
  `192.168.2.67:8443` backend for that exact SNI name and
  `mycelium.agora-one.wagar-house.myc`.
- Other SNI names go to the container's loopback TLS IPFS listener on 9443.
  The existing canonical CID host check, read-only methods and header filtering
  remain in effect. Unknown names are not Mycelium authorization exceptions.

The reviewed NGINX source is [subdomain.conf](../examples/ipfs-gateway/subdomain.conf).
The IPFS service owner should preserve this stream layer when redeploying.
This is a per-node TLS router, not mesh discovery or a new control plane.
Palisade can replace the ingress only with equivalent TLS passthrough; an
HTTP proxy's principal header cannot replace the original client certificate.

## Access

The existing Neo access issuer's public key is configured through a user-service
drop-in on both hosts. This trusts an issuer, not every client. The actual
`titan-agora-host-web-ajmwagar-20261011` signed grant has only `host-viewer`,
the two exact host-web node scopes, no SSH users or keys, and a 24-hour expiry.
It expires 2026-10-12 12:58:59 UTC; renewal is required and is not automated.
Signing/private client keys remain on Neo. Host TLS keys remain on each host.
DNS names, SNI routing and certificate pinning do not themselves grant access.

## Validation and rollback

1. Inspect the actual socket owners before changing ingress. Preserve unrelated
   services and existing namespace ownership.
2. Validate candidate NGINX configuration with the pinned deployed image,
   network and read-only TLS/config mounts before installing it.
3. Save the previous operator configuration, validate the live configuration,
   then reload NGINX gracefully. Do not replace the IPFS container.
4. Use verified CA trust and the human client certificate to fetch `/api/host`
   over port 443. Verify node identity and HTTP 200; never use `curl -k`.
5. Verify anonymous client TLS is rejected and a known CID still returns 200.
   Test normal DNS independently of explicit-address TLS probes.
6. For Agora rollback, restore
   `/etc/mycelium/ipfs-gateway/subdomain.before-mycelium-sni-20261011.conf`,
   validate and reload. For Titan, stop/disable `mycelium-titan-https.socket`
   and its service; the viewer on 8443 remains separate.

Browser trust/client-certificate selection is a separate client prerequisite.
Successful CLI probes do not establish that every browser has that identity.
