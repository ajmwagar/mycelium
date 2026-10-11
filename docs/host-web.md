# Optional host web view

The host view is an embedded, read-only page in `myceliumd`. It is off unless
`$MYCELIUM_HOME/host-web.json` exists. No frontend build, separate registry or
OIDC service is required. This initial slice is not deployed to the fleet.

## Authentication and authorization

HTTPS uses exactly the existing peer TLS configuration:
`MYCELIUM_PEER_CA`, `MYCELIUM_PEER_CERT`, and `MYCELIUM_PEER_KEY`.
The TLS client must present an unexpired certificate trusted by that fleet CA.
Fleet membership alone does **not** authorize a human to view the page.

The current human transport-binding seam is an administrator-installed bootstrap
mapping from the client's certificate SHA-256 digest to a principal. This is
temporary identity evidence, not a second ACL authority. It is not a signed
human identity binding and cannot be populated from arbitrary discovery facts.
Do not copy a peer's private key into a browser to impersonate a human.

After each complete, bounded HTTP request header, the daemon's existing authority resolver must find an
active signed access grant for that exact principal, with the `host-viewer` role
and the exact `host-web:<node_id>` scope. A role alone has no global authority.
Grant expiry, access revocation and delegated-signer revocation are evaluated
through the existing gossiped authority/access state, without contacting an IdP.
As with existing offline authorization, revocation takes effect after this node
receives it; there is no promise of instantaneous revocation during a partition.

OIDC browser login and production signed human-to-certificate bindings are
future integration gates. The view does not accept a bare JWT, browser cookie,
trusted forwarding header, or anonymous fallback.

## Manual configuration

Install a private `host-web.json` owned by the daemon's operating-system user:

```json
{
  "listen": "127.0.0.1:8443",
  "bootstrap_viewer_bindings": {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "alice"
  }
}
```

The digest above is an example, not a credential. Derive the real digest from
the viewer certificate's DER representation, never its private key:

```sh
openssl x509 -in viewer.pem -outform DER | openssl dgst -sha256
```

An existing authorized access issuer can publish a statement using the supported
`mycelium access publish --statement PATH --signing-key PATH --write` command.
Use a fresh grant ID/serial and actual validity timestamps; include the exact
principal, `roles: ["host-viewer"]` and `scopes: ["host-web:<node_id>"]`.
Do not grant broad SSH roles or reuse another user's identity to enable a page.

Restart the daemon using its existing service manager. Startup rejects malformed
configuration, missing TLS credentials and bind failures. The client can then
request `/` for HTML or `/api/host` for JSON. For a loopback test, use the server
certificate's real DNS SAN, with explicit resolution if necessary:

```sh
curl --cacert fleet-ca.pem --cert viewer.pem --key viewer.key \
  --resolve node.example:8443:127.0.0.1 https://node.example:8443/api/host
```

Do not use `-k`: a `.myc` DNS record does not make that name valid in an existing
certificate. A browser additionally needs the private CA trust and a properly
issued human client certificate imported through its supported certificate UI.

The page exposes local host identity, OS/architecture, daemon version, retained
health timestamps, uptime, memory totals and hardware counts. It omits process
arguments, hardware serials, addresses, credentials, access grants and the full
fleet inventory. Missing observations remain absent, not fabricated as healthy.

## LAN ports and recovery

To serve a LAN, select that host's actual LAN address instead of loopback. Nothing
is opened automatically on other peers. DNS maps a name to an address; it does
not proxy every peer through Neo or forward ports.

Port 443 requires an appropriate native socket/service-manager or owned ingress
configuration and a certificate covering the hostname. Do not run the entire
daemon as root just to bind a privileged port. This slice does not install a
privileged listener, ingress route, firewall rule, DHCP policy or certificate.
Port 80 is rejected by the HTTPS listener; any future HTTP listener must only
redirect to a configured HTTPS entrance, never return host data. A terminating
proxy cannot replace client authentication with an unverified principal header.

Changes to bootstrap bindings are read after headers arrive for each request,
not just during its TLS handshake. Removing the file
or making it invalid fails closed even while the listener remains bound; restart
to stop the listener. Changing its address requires a restart and denies new
requests on the old listener. Keep a known-good file for recovery and replace
configuration atomically. Removing a binding withdraws that bootstrap identity
evidence; use the existing signed revocation workflow to revoke authority.

The server bounds configuration to 16 KiB, headers to 8 KiB, concurrent requests
to 32 and each handshake/request/response to ten seconds. Connections close after
one request. Only GET `/` and GET `/api/host` are supported; there are no actions,
WebSockets, external assets or background browser polling.
