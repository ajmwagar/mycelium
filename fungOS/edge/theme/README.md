# Undergrowth

The default fungOS Canvas visual language uses charcoal surfaces and restrained
moss/lichen accents. `undergrowth.toml` is the canonical Canvas theme pack, not
a second palette in site CSS. The original distance-field kernel in
`render-undergrowth.rs` evokes overlapping bracket fungi and growth rings.
It uses no third-party Shadertoy source. The kernel is rendered once to P6 RGB;
Canvas uploads the retained image once and composites it behind real windows.
No wallpaper shader, animation timer, or shader GPU workload remains running.

The qualified Canvas GUI now persists imported image bytes in a private,
content-addressed store alongside its workspace file. A saved workspace retains
the image identity; restart verifies and decodes its matching local bytes.
Missing or corrupt assets fail visibly, without network fetching or repeated
per-frame retries. Import is bounded to 128 MiB and rejects symlinks.

Older saved workspaces need one owner-local `set_background` command with
`/etc/fungos-edge/theme/undergrowth.png`, followed by `workspace_save`, to populate
the store. The native compositor wallpaper remains independently configured.
The owner patch is included as `canvas-background-persistence.patch`; it is not
yet merged upstream. See [restart qualification](restart-qualification.md).

## Render and refresh

Run on Agora (or any Rust/FFmpeg host):

```sh
sh fungOS/edge/theme/refresh.sh render 1280 800 /absolute/output/theme
```

The image must match the actual connected DRM output, not an assumed mode.
The native compositor's `CANVAS_WALLPAPER` accepts this bounded P6 profile
(at most 4096×4096, exact 8-bit RGB bytes). Wrong dimensions or malformed images
fail startup visibly. Install the image at `/etc/fungos-edge/theme/undergrowth.ppm`
and the pack at `$CANVAS_CONFIG_DIR/themes/packs/undergrowth.toml` (or the existing
XDG Canvas configuration root). Select `fungos-undergrowth` through Canvas's
normal project theme selection; existing explicit project selections win.

Use a backed-up compositor service drop-in:

```ini
[Service]
StateDirectoryMode=0700
Environment=CANVAS_WALLPAPER=/etc/fungos-edge/theme/undergrowth.ppm
```

For new images include that drop-in and rendered asset in the edge rootfs.
The same deterministic preparation can stage those files and the default `dock`
project theme selection into an edge rootfs (never `/`):

```sh
TMPDIR=/home/ajmwagar/.cache sh fungOS/edge/theme/refresh.sh prepare-rootfs /absolute/staging/rootfs 1280 800
```

The `canvas-display` capability includes the distribution-owned Xcursor themes
and libseat runtime; use its seatd broker for a headless system service. The
whiteglass cursor comes from Debian's `xcursor-themes` package; its license
and attribution remain in `/usr/share/doc/xcursor-themes/copyright`.

For existing peers, publish the owner-built GNU2.36 `canvas-linux` binary as a
signed Mycelium package first; seed verified bytes, explicitly activate only
that package, and restart only `canvas-compositor`. Preserve the previous
package link and drop-in for rollback. Guest commands require
`MYCELIUM_HOME=/var/lib/mycelium MYCELIUM_NO_AUTOSTART=1`.
Do not copy a signing private key to a peer, reboot, or change automatic policy.
Check service state, Wayland mapping, actual framebuffer and Unibus receipt;
if readiness fails, restore the prior package/drop-in and compositor session.

## Honest desktop captures

Arrange real applications using the native window manager, then on the QEMU host:

```sh
sh fungOS/edge/theme/refresh.sh capture /run/qemu-canvas-demo/demo.qmp /absolute/output/captures desktop
```

This performs only QMP capability negotiation and `screendump`; it sends no input
and never starts/stops a guest. It produces untouched PPM/PNG plus timestamp,
source commit and PNG SHA256 provenance. A capture must show the real current
session. Keep terminal output free of secrets; do not composite pretend apps,
crop failures away, or present the background preview as a desktop screenshot.
Copy chosen PNGs and provenance into the existing site's `dist/assets/` and
replace its screenshot image references. Site publishing is a separate action.

If QMP is occupied by the stream owner, do not disconnect it. Use the read-only
loopback VNC capture instead:

```sh
sh fungOS/edge/theme/refresh.sh capture-vnc 127.0.0.1:5901 /absolute/output/captures desktop
```

When copying these tools outside a Git checkout, set `FUNGOS_SOURCE_COMMIT` to
the exact source revision. QMP capture has a 20-second outer timeout; the VNC
helper bounds connect/read/write to ten seconds and rejects partial frames.
