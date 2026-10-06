# fungOS edge: safe package activation

The base image remains headless. Unibus and Canvas are optional edge applications,
not base dependencies. Build pipelines produce their artifacts; Mycelium verifies,
distributes and activates authorized updates. Applications keep their own protocols.

## Native display and headless targets

See [profile build commands](../profiles.md). Both edge variants support amd64
and arm64 rootfs builds. Display edge uses **Canvas Linux itself** as the
Wayland/KMS compositor; the separate iced Canvas application is a Wayland client.
Do not introduce Xorg, Weston or Sway as a replacement compositor. Headless edge
does not start either Canvas process and carries no display dependency set.

The [QEMU compositor unit](qemu/canvas-compositor.service) launches the signed
`canvas-linux` executable. Its source must include the `compositor` feature and
`desktop-compositor start`; an older same-named binary is not equivalent. The
home-pi deployment already uses this native path. QEMU configuration remains an
experimental root-owned session and requires a kernel-matched DRM driver; do not
copy that unit unchanged onto a Pi. Production edge needs a least-privilege seat.

The application readiness checks below do not yet prove compositor scanout.
Do not automatically activate compositor releases based solely on a Wayland
socket: the compositor can legitimately run headless without a usable DRM output.
Require an application-owned output/renderer health check before enabling that
package's automatic activation policy.

## Implemented first slice

Linux package activation can bind to an existing systemd service through
`$MYCELIUM_HOME/software-services.json` (regular file, mode `0600`). A release
cannot supply this local configuration or arbitrary commands. See
[`edge-software-services.json`](../qemu/tests/edge-software-services.json) for a
complete example and [`edge-software-policy.json`](../qemu/tests/edge-software-policy.json)
for node selection and automatic rollout policy.

The service's `ExecStart` must directly launch
`$MYCELIUM_HOME/software/PACKAGE/current/EXECUTABLE`. Health is a bounded local
Unix-socket or loopback TCP request/response. Verification requires the supervised
PID to own that listener, execute the signed digest and remain healthy across
three samples. An unrelated listener cannot stand in for the updated process.

Activation verifies authority, platform, digest and size before stopping the
service; serializes writers; preserves immutable version directories; then switches
the current link, starts and checks readiness. Failure restores and checks the
previous version. Failed recovery is an error, not successful rollback. An initial
failed install removes the current link. Results persist in
`software/PACKAGE/last-activation.json`.

Automatic activation requires an explicit native service binding. Manual unbound
activation remains byte promotion only; it does not prove application health.
The shared Linux update timer runs self-updates followed by package policy
reconciliation, with cache-age gates, deterministic rollout staggering and retry
backoff. Missing package policy is a no-op; malformed policy fails loudly.

## Manual runbook

1. Install the native unit and owner-only service binding. Keep the unit's existing
   security settings; don't replace a production unit with the test fixture.
2. Publish an artifact with `mycelium packages publish` using a signer already
   authorized by the shared authority system.
3. Preview with `mycelium software plan POLICY.json --json`.
4. Install policy with `mycelium software policy set POLICY.json --write`.
5. Run `mycelium software auto-run --json` after the artifact's age and rollout
   gates permit it, or let `mycelium-update.timer` do so.
6. Inspect `mycelium software status --json`, the native unit, and the persisted
   activation result. Disabling automatic policy does not remove installed bytes.

## Reconciling installed applications

`mycelium software reconcile --dry-run --json` observes the installed release
link, signed byte digest and any locally bound native service. A matching version
alone is not compliance: a stopped service, wrong running executable, failed
application readiness check or altered installed bytes returns `state: drifted`
with a `drift` reason. This command performs no service lifecycle changes.
`software status` is the last persisted report, not a fresh health observation.

`mycelium software reconcile --write --json` repairs unhealthy bound services
through the same activation transaction used for upgrades, even at the same
version. Healthy current applications are left running. Candidate bytes must be
cached and signature/size/digest verified before any service is stopped; failed
readiness still invokes checked rollback. An altered immutable release fails
loudly and is not overwritten. That integrity incident needs explicit operator
recovery, not an automatic "repair" that hides it.

For installed packages with `updates.mode: automatic`, the existing update timer
also attempts same-version service repair after the cache-age, deterministic
rollout and retry-backoff gates permit it. Only locally bound services are
eligible; manual packages remain manual. To intentionally keep an application
stopped, set its update policy to manual first. Automatic policy does not install
a previously uninstalled package, authorize a reboot, rename a host, change
networking or create users. Those remain separate existing capabilities.

The observer uses a single bounded readiness sample; post-activation verification
still requires three stable samples from the supervised process. Readiness checks
and service inspection run outside the mesh RPC event loop. This is a bounded
native-service adapter, not a second supervisor or application scheduler.

### QEMU reconciliation evidence, 2026-10-06

Built the clean Mycelium source on Agora for `x86_64-unknown-linux-musl`;
type checking and all 85 daemon tests passed (test temporary files used a
dedicated cache directory because the host `/tmp` quota was exhausted).
Published signed Mycelium `0.1.12` on the guest-only `fungos-qemu-test` channel
using the existing fleet release authority. The guest received its manifest
through gossip; bytes were explicitly transferred and seeded, then installed
through signed self-update. Installed SHA-256:
`1e85bc9004463cfbcc66a6b7a4e866bbf082ece0bf18dd941ca517c012078b4b`.
This does not claim automatic artifact fetching or a fleet-wide rollout.

- Stopped the guest's Unibus router: dry-run reported `drifted` with
  `native service is not active`, despite its installed version still matching.
- Explicit reconciliation restarted and verified the same signed release.
- Repeated reconciliation left the healthy supervised PID unchanged.
- A second deliberate stoppage was repaired by `software auto-run`; its next
  invocation returned an empty `applied` list and current application status.
- The router restart exposed a native dependency gap: `Requires=unibus-router`
  stopped Canvas's adapter, but starting the router did not pull it back in.
  The display-only [router drop-in](qemu/unibus-router.service.d/20-canvas-adapter.conf)
  adds `Wants=canvas-edge.service`. Native systemd unit validation passed;
  repeating the repair started both services. The adapter's existing restart
  policy handles the short interval before the router begins accepting connections.

The update timer was paused only during fault injection and restored afterward.
No reboot, GPU handoff, network change, identity rotation or account creation
was performed. Compositor automatic updates remain gated on output readiness.

## QEMU evidence, 2026-10-05

The native fixture is Rust, not a substitute implementation of Unibus or Canvas:
[`edge-update-probe.rs`](../qemu/tests/edge-update-probe.rs) and
[`edge-update-probe.service`](../qemu/tests/edge-update-probe.service).

- `1.0.0`: signed initial installation passed PID-bound readiness.
- `1.1.0`: deliberately exiting binary failed; `current` returned to `1.0.0`
  and the previous service passed readiness again.
- `1.2.0`: automatic policy reconciliation selected the eligible signed package,
  changed `current` to `1.2.0`, and persisted `verified_service: true`.
- The updated Mycelium daemon itself was installed through signed self-update.

This proves the package transaction in the running persistent-root QEMU guest.
That fixture did not install Unibus or Canvas; the subsequent native integration
below is a separate test.
This slice is Linux/systemd only. It does not yet provide a power-loss recovery
journal, atomic multi-package rollout, or macOS launchd activation.

## Native Canvas integration evidence, 2026-10-05

The persistent amd64 QEMU guest now runs real Unibus, `canvas-linux` and Canvas.
Canvas Linux owns Wayland/KMS directly, with Canvas on its `wayland-5` socket.
The Xorg experiment is disabled; neither Xorg nor Weston runs in the session.

- Built the compositor on Agora with `--no-default-features --features compositor`;
  type checking passed, 36 tests passed and one live-session test was ignored.
- Built the executable using `cargo zigbuild` for
  `x86_64-unknown-linux-gnu.2.36`, not the build host's newer glibc.
- Published and installed `canvas-linux` through signed Mycelium package
  activation: digest `d3ad57a350f1704b3fa713c8da8a8140f234d1aa796c6beb83c5b174a6c13592`.
  This was manual unbound activation; it is not an automatic compositor-health
  certification. Application display verification was performed separately.
- The compositor reported DRM output on `/dev/dri/card0` at 1280x800. A QEMU VNC
  screenshot contained the Canvas clock, and the home-pi TV receiver contained
  a fresh matching clock frame over the existing Unibus stream.
- Rebooted the guest: Mycelium, Unibus, Canvas compositor and Canvas all returned
  active; Canvas's structured inspect returned `outcome.status: ok`. Peer
  certificate and machine-id digests were unchanged.
- Restored the original peer configuration and manual application policy,
  and removed the temporary package-signing private key from the guest.

The build used an isolated Canvas source snapshot because the main checkout
lacks the deployed native compositor. A missing `SocialFeed` renderer arm was
made explicitly unsupported, matching the existing pending-renderer behavior.
This source must be reconciled into the owning Canvas repository before a
production Fab release; fungOS does not vendor or own the compositor source.
The clock was a diagnostic command, not a configured default after reboot.

All four rootfs variants were built, inspected and their SHA-256 files verified
on Agora (uncompressed tarballs):

| Profile | amd64 | arm64 |
| --- | ---: | ---: |
| edge | 468 MiB | 483 MiB |
| headless-edge | 185 MiB | 215 MiB |

These contain Debian runtime dependencies, not signed first-party executables,
identity, enrollment tokens or board boot firmware. The running QEMU experiment
uses the earlier persistent base plus signed application installation; it is not
yet a boot test of each newly built profile tarball.

## Automatic applications and Unibus integration, 2026-10-05

Installed [automatic policy](qemu/software-policy.automatic.json) in the running
QEMU guest. The shared `mycelium-update.timer` is enabled; its native oneshot
runs package reconciliation. Automatic activation advanced Canvas to `0.1.5`
and Unibus router to `0.1.1`; both persisted `verified_service: true` with no
error and returned `current`. These test versions republish the existing healthy
bytes, not new upstream application changes. The earlier broken-application
test established rollback; no new broken release was distributed to the fleet.

Releases were signed on Neo using the existing fleet release authority, not
a private signing key installed in the guest. The guest trusts its public key
and receives signed manifests through peer gossip. Its additional seed uses
Neo's certificate-valid address; a LAN address not present in the certificate
was correctly rejected. Agora's installed CLI predates package support, so it
remains a fallback seed, not the sole update source. Signatures and byte hashes
remain mandatory. Automatic policy is scoped to this guest and test channel.

The [Canvas Unibus adapter](qemu/canvas-edge.service) was installed through
signed manual activation and registered as `fungos-canvas` with the local router
at `127.0.0.1:18790`, advertising `fungos-qemu-screen`. Its initial artifact was
copied to the content-addressed cache before activation; this is not evidence
of automatic artifact fetching for that adapter. The adapter is not in the
automatic policy until it exposes a bounded application-owned readiness check.
The actor list is empty: registration does not grant remote command authority.
This local adapter does not establish cross-site Unibus routing.

Adding the adapter exposed a cold-boot directory race: it could create Canvas's
control directory with permissions Canvas correctly rejected. Both units now
use `UMask=0077`, and Canvas normalizes its owned runtime directories to `0700`
before launching, matching the home-pi setup. The final reboot returned all five
services active, retained the installed versions and enabled update timer, and
Canvas inspect succeeded without a directory-repair diagnostic first.

The compositor remains manually managed until output/renderer readiness exists.
Do not infer compositor health from the Canvas app's inspect response alone.
Boot-ready Pi firmware/kernel images remain a separate next slice.

## Boot security is a separate profile

Genesis owns installation; system cryptsetup and Clevis own encrypted-root unlock;
Tang runs as a separately operated service. Mycelium plans reachability and manages
the enrolled machine, not the encryption algorithm or Tang server implementation.

For a fresh encrypted install, the next test must retain and verify an independent
recovery key, pin the expected Tang advertisement through a trusted channel, include
Clevis and networking in the initramfs, and prove both network unlock and recovery
after a reboot. Loss of Tang connectivity must not become loss of recovery access.
Tang reachability alone is not server authenticity or authorization to enroll.

Existing Deckard/NVR enrollment must not reinstall, reformat, re-encrypt or rebind
their disks. Existing LUKS policy and recovery material must be assessed separately.
No encrypted-root/Tang reboot has been verified by the edge update fixture.
