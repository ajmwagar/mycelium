# fungOS edge: safe package activation

The base image remains headless. Unibus and Canvas are optional edge applications,
not base dependencies. Build pipelines produce their artifacts; Mycelium verifies,
distributes and activates authorized updates. Applications keep their own protocols.

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
Real Unibus/Canvas artifacts and their application-specific readiness contracts
are the next integration step; neither application was installed by this test.
This slice is Linux/systemd only. It does not yet provide a power-loss recovery
journal, atomic multi-package rollout, or macOS launchd activation.

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
