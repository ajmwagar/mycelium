# Pairing presentation

`mycelium sync export --presentation` emits a public connection projection with
the exact existing rendezvous JSON QR payload and a black/white SVG QR. It does
not mint invitations, expose keys, grant access, or enroll anything. Export
rejects expired/future hints. Direct socket addresses are **hints**, not proven
reachability or automatically classified LAN/WAN addresses. Site and friendly
name must come from the authorized display owner's target selection, not from
a guessed IP subnet. The exported rendezvous is not a signed identity proof;
normal fleet membership, endpoint binding and transport authentication remain
mandatory when connecting.

## Canvas / TV adapter

`config/canvas/pairing.lua` composes existing Canvas `asset` and `rich_card`
surfaces. An owner adapter should:

1. Select an authorized source peer and export its presentation.
2. Import `qr_svg` into the receiving Canvas asset store using its existing
   owner API, retaining its hash/media-type/byte-length receipt. Renderers that
   only support raster image assets must rasterize with their owning adapter
   first and pass its PNG receipt; this source does not claim SVG support in
   every current renderer.
3. Call `render(projection, owner)` with `target_endpoint_id`, owner-clock `now`,
   `qr_asset`, target name/site, display name and current document revision.
   Use `tv=true` for side-by-side television layout; the compact window uses
   a vertical layout. Names identify the target separately from the display.
4. Import the resulting workspace through the revision-bound Canvas API,
   preserving the selected workspace unless activation was explicitly requested.
5. Refresh before `expires_at`, and re-render at expiry even if the source is
   offline. Expired renders contain no QR surface. A retained image by itself
   is **not** a continuously safe pairing screen.

The same owner document is suitable for supported fungOS/FireTV Canvas asset
renderers. Native Apple tvOS renderer integration is not claimed here; its
owner must implement the same asset/document and expiry behavior first.
No screens are activated by export or by this pure Lua composition.

Scanning presently produces rendezvous JSON: save it as a file, then use
`mycelium sync join <rendezvous.json> --write` and the existing daemon restart
workflow. There is no new mobile deep-link or browser enrollment flow.

Sensitive single-use invitation QR is deliberately unsupported by this
renderer. It requires a separate explicitly authorized issuer path plus
non-retained recipient delivery and immediate expiry/revocation clearing.
Read-only host pages must not silently gain issuance privileges.

## Verification

Run `lua config/canvas/pairing-test.lua` for compact/TV layout, separate display
identity, expiry, wrong-target, future-observation and invite rejection checks.
Run `cargo test -p mycelium-cli --features iroh-sync presentation_is_public` for
exact payload compatibility and timestamp validation. Live asset importing,
scheduled expiry refresh and native TV rendering still require owner adapter
wiring; this slice does not claim a working live feed from an exported file.
