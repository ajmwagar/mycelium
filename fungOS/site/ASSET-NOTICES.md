# Platform marks

## fungOS mark

`dist/assets/fungos.svg` and `fungos-icon.png` are original procedural artwork,
rendered from fungOS' `brand/render-undergrowth.rs`. They share the
Undergrowth wallpaper's organic contour field. Code and artwork are MIT OR
Apache-2.0; no third-party shader was used. The fungOS name and logo are project
marks, not a claim of registered status. Software licenses do not grant trademark
rights; see the distribution repository's `TRADEMARKS.md`.

The platform SVGs in `dist/assets/` are sourced from Simple Icons (CC0-1.0):

- `amazonfiretv.svg`: https://github.com/simple-icons/simple-icons/blob/13.0.0/icons/amazonfiretv.svg
- `appletv.svg`: https://github.com/simple-icons/simple-icons/blob/develop/icons/appletv.svg
- `meta.svg`: https://github.com/simple-icons/simple-icons/blob/develop/icons/meta.svg
- `htcvive.svg`: https://github.com/simple-icons/simple-icons/blob/develop/icons/htcvive.svg

Upstream license: https://github.com/simple-icons/simple-icons/blob/develop/LICENSE.md
Brand names and marks belong to their respective owners. Platform identification does not imply endorsement.

# Desktop captures

`dist/assets/fungos-{workspace,desktop,terminal}.png` are untouched 1280×800
framebuffer captures of `fungos-edge-qemu-01` on Agora, 6 October 2026. The native
Canvas Wayland/KMS compositor owns the display; the applications are real Weston
Wayland terminals. No window, app content or feature UI was composited into them.
Each image has a matching `.provenance.txt` with capture time, source revision,
transport and PNG SHA256. Capture used read-only loopback VNC because the live
stream owner held QMP. The frozen fungal background is original procedural
artwork rendered from `fungOS/edge/theme/render-undergrowth.rs` in Mycelium;
no third-party Shadertoy source was copied. Cursor assets are distribution-owned
`xcursor-themes`; their attribution remains in the guest's
`/usr/share/doc/xcursor-themes/copyright`.
