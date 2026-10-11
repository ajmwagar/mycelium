# Optional host web view

## Standard HTTPS port without a root daemon

`mycelium-https-forwarder` accepts exactly one native service-manager socket
on an explicit local address, port 443. Launchd (macOS) or systemd (Linux)
opens the privileged listener; the relay runs as `nobody`/`DynamicUser`, without
TLS keys or authority. TLS bytes pass unchanged to port 8443 on loopback or
the same local bind address. Remote forwarding is rejected. Mycelium performs
the original mTLS authentication and signed-grant authorization.

Templates live in `config/host-web/`. Replace the documentation address with
the host's actual chosen local address and use the matching backend address.
Build the relay with `cargo build -p mycelium-cli --release --bin
mycelium-https-forwarder`, install it root-owned at
`/usr/local/libexec/mycelium-https-forwarder`, and retain its prior version
before replacement. It is deliberately independent of peer keys and the
daemon process.

On Linux, install the `.socket`/`.service` files in `/etc/systemd/system`, run
`systemctl daemon-reload`, then `systemctl enable --now mycelium-https.socket`.
The daemon may keep its existing unprivileged 8443 listener. On macOS, install
the plist root-owned in `/Library/LaunchDaemons`; create the stderr log owned
by `nobody` before `launchctl bootstrap system PLIST`. Socket activation starts
the relay on demand. Rollback: boot out the launchd job or disable/stop the
systemd socket and service. Neither action changes the 8443 daemon listener.

Verify an authenticated HTTPS request returns 200 on 443, anonymous TLS is
rejected, and the relay's process identity is unprivileged. Certificate SANs,
browser trust and identity preferences must cover the exact URL. This relay
does not install DNS, certificates, HTTP redirects or a wildcard listener.
Local lease renewal is read on service-catalog requests without a scan;
deleted or expired local files withdraw immediately, without extending TTL.
Remote observations still depend on existing signed gossip freshness.

## Site index

Set `"index": true` in the existing private host-web configuration to serve
the discovery index at `/` and `/sites`; `/api/sites` is its JSON projection.
`/host` and `/api/host` retain the local host view. Index mode is off by default.
Restart after changing it; a configuration change denies requests on the old
listener until restart.

Index access needs its own existing signed grant: role `discovery-viewer`, exact
scope `discovery-index:<serving-node-id>`, and the same explicitly bound human
TLS certificate. A `host-viewer` grant does not grant fleet inventory access.
The index groups observed signed peer identities by site, with explicit freshness
(five minutes) and original observation timestamps. It is not a health assertion
or a complete inventory promise. No addresses, interface details, credentials,
process arguments, or hardware serials are projected. More than 512 peers or a
256 KiB response fails loudly; there is no silent truncation.

Unibus owns its separate capability/zone-filtered viewer, not this page. Discovery
can provide its entrance; it cannot substitute Mycelium's grants for the router's
own authorization.

### Pairing direction (not implemented by this read-only view)

A local page can display the existing public signed peer-to-Iroh identity
binding as a connection QR, together with observed local addresses and clearly
labelled WAN/STUN hints. A connection ticket establishes reachability, not
membership or permission. Address hints may expire or change without changing
the bound endpoint identity.

An invitation is different: its single-use, expiring claim is sensitive. Issuing
or revealing one must be an explicit authorized action through the existing
pairing issuer, with enrollment authority, expiry and requested roles visible.
Do not mint invitations on page load, put private keys in a QR, bake access roles
into the stable endpoint binding, or assume every peer can issue invitations.

`localhost.myc`, if enabled, must resolve to this machine's loopback interface,
never another peer or the site gateway. Localhost is not administrator evidence;
authenticated requests and action authorization are still required. An
unenrolled first-boot interface needs a separate local-owner bootstrap policy,
not an anonymous exception to the enrolled host view. Follow-up is tracked as
`mycelium-pairing-ui`.

## Optional service-name advertisement

Set `advertise: true` in `host-web.json` only when the listener binds an explicit
non-loopback address. Default is false. The page then owns
`application-services.d/mycelium-host-web.json`, renewing a 120-second lease
every 30 seconds after a successful bind. Listener failure, invalid/disabled
configuration, or advertisement-write failure stops renewal. This is availability
metadata, not a permission grant; it does not change human authentication.

Mycelium imports the file during normal scans and gossips its original expiry.
With `service_aliases: {"mycelium-host-web": "mycelium"}` in the optional DNS
resolver's settings, fresh matching peer evidence yields
`mycelium.HOST.SITE.myc`. Unibus pages use the same naming/projection mechanism
with the `unibus-viewer` kind and `unibus` label. Neither app installs ingress,
DNS, or certificates automatically. Use the advertised port and issue a server
certificate covering the exact service hostname. Keep scan cadence below 120
seconds; file removal is not immediate distributed revocation.

The host view is an embedded, read-only page in `myceliumd`. It is off unless
`$MYCELIUM_HOME/host-web.json` exists. No frontend build, separate registry or
OIDC service is required. This initial slice is not deployed to the fleet.

## Authentication and authorization

HTTPS uses exactly the existing peer TLS configuration:
`MYCELIUM_PEER_CA`, `MYCELIUM_PEER_CERT`, and `MYCELIUM_PEER_KEY`.
The TLS client must present an unexpired certificate trusted by that fleet CA
or an explicitly pinned bootstrap human leaf described below.
Fleet membership alone does **not** authorize a human to view the page.

Optionally set `server_identity` to an object containing absolute `certificate`
and `private_key` file paths. This changes only the host web server's HTTPS
identity, allowing a certificate with the host's `.myc` DNS SAN without changing
the peer certificate or its signed transport binding. The client verifier still
uses `MYCELIUM_PEER_CA` plus any explicitly pinned bootstrap human leaves. Omitting it
uses the existing peer server certificate. Both fields are mandatory when set;
invalid paths, unreadable PEM, mismatched keys and bind errors fail startup.
Changes to these files require a daemon restart.

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

### Native browser bootstrap compatibility

Some native certificate stores cannot use an Ed25519 fleet issuer chain.
An optional `bootstrap_viewer_certificates` array supplies absolute paths to
individual human certificates trusted **only by this host web listener**. Each
file is limited to 64 KiB and must contain exactly one PEM certificate whose DER
digest is already in `bootstrap_viewer_bindings`. At most 64 leaves are allowed.
There is no new CA, no peer TLS verifier change and no automatic enrollment.
Possession of that human private key still grants nothing without the active,
exactly scoped signed access grant. Removing the binding denies requests;
changing the leaf-path list denies requests until the daemon is restarted.

For a native bootstrap, a short-lived self-signed P256 human certificate with
`clientAuth` can be pinned this way, and a dedicated self-signed P256 HTTPS leaf
can be trusted for the specific hostname. Keep both separate from peer keys.
This is an explicit administrator-installed compatibility bridge, not a
canonical human identity issuer or a replacement for signed identity bindings.

When creating a password-protected P12 for macOS Keychain import, OpenSSL 3's
default encoding may produce a generic MAC verification error. Its compatible
export options are `-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1`.
These affect the local encrypted import container, not TLS encryption. Use a
random strong password via a protected password file (`-passout file:PATH`),
restrict both artifacts to mode 0600, and never put the password in a command
argument, repository or log. Import using the native UI, then verify that the
identity is usable for TLS client authentication before claiming browser access.

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

### Site-index navigation

When `index` is enabled, the authenticated `/sites` index includes site anchors,
an expandable site-membership tree and links to individual peer observations.
Anchor identifiers are generated from presentation order, never interpolated
from untrusted host or site names. Names remain HTML-escaped. Freshness markers
describe retained observations, not successful browser connectivity. Membership
does not imply a physical or overlay link. These links stay inside the authorized
index; they do not yet open remote host pages or application endpoints.
