# Canvas restart qualification — 2026-10-06

Qualified only on `fungos-edge-qemu-01`; no fleet rollout or host reboot.

Canvas source is `87018dd` plus `canvas-background-persistence.patch` (SHA256
`105447ff1cf84c55bd82884067e4912fd60baf2f93cf8d0dc50de5d607e00d57`).
The isolated owner worktree is `/private/tmp/canvas-fungos-wallpaper`;
upstream integration remains tracked by `dock-9b6`.
Dependencies: Unibus `f754f0cb076665a9a229e39b95a8f7ecf3175b0f`,
Isochrone `bfd1ec2ae7ba46e6cadb8b94ed8e44e913a9951c`.

Checks and three focused persistence tests passed on macOS and Linux, with
`lua-scenes` enabled. Agora built the GNU/glibc 2.36 compatible binary using
`cargo zigbuild --locked --release --target x86_64-unknown-linux-gnu.2.36
-p canvas --bin canvas --features lua-scenes`.
Signed Mycelium package `canvas` version `0.1.6`, channel `fungos-edge-test`,
binary SHA256 `cf349fd79e0f7bc20d223d0f9d6935759c8eee06105024eb64040b0f48292cf7`,
passed native activation readiness. Version `0.1.5` remains available for rollback.

## Live verification

1. Import the background and save workspace `dock` through the local control socket.
2. Verify its persisted object digest and private permissions: state/cache 0700,
   object 0600; workspace store `/var/lib/fungos-edge/workspaces.json`.
3. Temporarily move the source PNG to a recoverable path, with an EXIT trap
   restoring it. Restart Canvas while the source is absent.
4. Inspect the restarted GUI: image identity retained, no restore error events.
   Compositor PID stays unchanged. Restore the source PNG.
5. Add the display-edge `Wants=canvas-edge.service` drop-in and repeat restart.
   Its existing Requires consumer now returns automatically.
6. Verify all six services active: Mycelium, Shroud, Unibus router, Canvas,
   Canvas compositor, Canvas edge. The adapter registers its screen anchor again.

The [unaltered framebuffer capture](background-restored-20261006.png) shows
the restored fungal wallpaper and two real Weston terminals. Captured through
read-only loopback VNC after the restart and after restoring the source file;
the source-absent check above was separately verified through the control socket.
PNG SHA256: `5c14533f75c5e2dbd3f917b5edbdc2f9cc9aac874d1bf10d8dff711e5db65edc`.

This does not qualify a full guest reboot, remote asset retrieval, cache garbage
collection, or automatic deployment to other peers.
