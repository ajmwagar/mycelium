#set page(paper: "a4", margin: 24mm)
#set text(font: "Arial", size: 11pt, fill: rgb("26382e"))
#set par(leading: 0.8em)
#set heading(numbering: none)

#text(size: 12pt, tracking: 1.5pt)[fungOS / MYCELIUM]
#v(10mm)
#text(size: 30pt, weight: "bold")[A document on the mesh.]
#v(3mm)
#text(size: 14pt, fill: rgb("587461"))[IPFS content. Mycelium DNS. Trusted HTTPS.]
#v(10mm)

This is an actual PDF, served by Agora's Kubo node through the
Mycelium-owned IPFS namespace. It is not a gateway status page.

== How you reached this page

The browser opens `https://CID.ipfs.myc/`. Mycelium DNS resolves that
namespace to an explicitly authorized gateway peer's fresh, reachable LAN
address. The gateway serves the bytes identified by the CID from Kubo.

HTTPS uses the fleet's browser web CA. The gateway's certificate covers
`*.ipfs.myc`; a Tailscale hostname is not needed for this entrance.

== What this proves

- PDF bytes arrive through the CID hostname.
- The response is identified as `application/pdf`.
- The CID identifies the document independently of its gateway address.
- GET, HEAD and byte-range reads work without exposing Kubo's admin API.

== Access boundary

This LAN gateway is read-only, but it has no per-document ACL. Discovery
does not grant access, and a CID is not a password. Keep private content
encrypted until a separate authorization design is in place.

#v(12mm)
#line(length: 100%, stroke: 0.6pt + rgb("b1c4b5"))
#v(3mm)
#text(size: 9pt, fill: rgb("587461"))[Gateway rendering check - 11 October 2026]
