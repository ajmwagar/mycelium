# Browser HTTPS trust

The fleet's Ed25519 CA continues to authenticate peer transports. The optional
P256 **web CA** authenticates HTTPS servers to browsers; it cannot enroll peers,
issue SSH credentials or grant viewer access. Existing human certificate bindings
and signed access grants are still evaluated on each request.

## Controlled issuer workflow

Run once on the administrator's issuer host:

```sh
mycelium web-ca init --path "$HOME/.mycelium/web-authority" --write
```

Back up `ca-key.pem` securely. Only the issuer holds it. Distribute the public
`ca.pem` through an authenticated channel and verify its SHA-256 fingerprint
before trusting it in the browser/OS certificate store. This is one trust
decision for the web CA, not one decision per host. Browser client-certificate
selection prompts are separate from server trust.

On each enrolled target (including later renewals):

```sh
mycelium web-ca request --path "$HOME/.mycelium/host-web" --write
```

The HTTPS key is generated locally and reused for renewal. `request.json` carries
the CSR, issuance timestamp and an existing-peer-key signature. Share only that
public request with the issuer, never either private key. Requests expire after
ten minutes. On the issuer:

```sh
mycelium web-ca issue \
  --ca "$HOME/.mycelium/web-authority" \
  --request /path/to/request.json \
  --output /path/to/new-generation --write
```

The signer verifies proof of peer-key possession and requires a fresh authenticated
peer observation. Hostname and administrative site are derived from that signed
identity, not CSR extensions. Issued SANs are `HOST.SITE.myc` and
`mycelium.HOST.SITE.myc`; wildcards and arbitrary domains are not accepted. Only
an administrator's explicit `--index` adds `mycelium.myc`. This does not select
the DNS index owner; that remains DNS policy. Movement does not rotate peer keys;
an authorized hostname/admin-site change requires a new certificate.

Return `server.pem` and public `ca.pem` to the target through an authenticated
channel, then:

```sh
mycelium web-ca install --path "$HOME/.mycelium/host-web" \
  --certificate /path/to/new-generation/server.pem \
  --ca /path/to/trusted/ca.pem \
  --hostname HOST.SITE.myc --write
```

Installation checks chain, server purpose, hostname, at least two days of
remaining validity, and matching local private key before atomic replacement.
The prior leaf is retained as `server.pem.previous`. Configure `server_identity`
in `host-web.json` to those absolute `server.pem`/`server-key.pem` paths.
New web handshakes reload the certificate; existing connections and peer sync
are not restarted. Invalid replacements fail closed and log an error.

## Renewal and boundaries

Leaves last seven days. Repeat the request/issue/install workflow before the
last two days. There is **no unattended signing endpoint or fleet scheduler in
this slice**: issuer custody and explicit invocation authorize issuance. A known
peer observation alone must not become an automatic authorization rule. An
unattended issuer will also need current membership revocation and name-ownership
policy before accepting requests; do not expose these commands as an anonymous
CSR API. Browser leaf revocation/CRL distribution is not implemented here.

Do not install the web CA as a peer CA or client-verification root. It does not
replace short-lived human viewer certificates or ACL renewal. Installing server
trust alone cannot bypass viewer authorization.

For rollback, validate `server.pem.previous` against the trusted root, matching
key and hostname before atomically restoring it. Never restore an expired leaf
or disable TLS validation to keep a page available. A failed `.next` write is
retained for inspection; remove only that exact file after investigating.
