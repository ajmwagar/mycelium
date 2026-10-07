# Update safety

## Edge guest qualification, 2026-10-07

The persistent edge QEMU guest on Agora completed a signed Mycelium bootstrap
to `0.1.20`, followed by peer-only download and automatic activation of `0.1.21`.
The latter's installed SHA-256 is
`1ad2cc3ed709d3a2718c38546382252533ef44b24c7357a7cf4e561c6ff4193c`.
No manual artifact seed was used for `0.1.21`. Its partially downloaded artifact
survived the first reboot and completed through the mesh. A second reboot
retained that installed digest, enrollment certificate, peer identity, machine
ID, and SSH host key. The updater timer and Mycelium, Unibus router, Canvas,
Canvas compositor, and Canvas edge adapter were all active afterward.

The first signed candidate (`0.1.18`) failed the older updater's startup probe;
the previous daemon was restored. The fixed updater retries the complete
PID-bound readiness probe with a ten-second deadline, rather than failing on a
transient first RPC or waiting indefinitely on a silent socket. The guest CLI
now dispatches to its managed binary. Distribution follows persisted policy
rather than a stale bootstrap environment channel. Compositor control/status
sockets now live beneath its private systemd runtime directory; keeping them in
persistent storage prevented Canvas from starting after reboot. User-facing
Canvas configuration and workspaces remain persistent.

Checks passed on Agora: 97 daemon tests (one disruptive test ignored in this
run), all 59 CLI tests, and the QEMU overlay checks. Agora's default `/tmp`
quota caused the first full CLI run to fail; rerunning with a fresh cache-local
`TMPDIR` passed.

After separately authorized Neo reconciliation, the isolated-channel manifests
reached the guest. `software auto-run` selected and activated Canvas `0.1.9` and
Unibus router `0.1.5` through their existing native service bindings. These are
qualification versions of already-cached known-good application payloads, not
new upstream builds or proof of downloading fresh application bytes.

A signed Unibus router `0.1.6` fixture deliberately exits with status 42. It was
manually seeded after its trusted manifest arrived, then explicitly reconciled.
Native readiness rejected the candidate and restored `0.1.5` with digest
`792bcfa3b87895b952e96a27060b4812e87dc62f5ed504432d2a2970c40d8319`.
The Unibus router, Canvas edge adapter, Canvas and compositor were all active;
the pending activation checkpoint was absent and the failure remained visible
in `last-activation.json`. This is a live single-application rollback proof, not
an automatic fault-injection or whole-set transaction proof.

Neo's duplicate shared-home processes were removed without changing enrollment
identity or stopping a separate EdgeOS test daemon. Publisher startup was then
severely delayed by concurrent system load (approximately 430, CPU fully busy).
A process sample showed cached signed-envelope verification during daemon boot.
Use `MYCELIUM_NO_AUTOSTART=1` while restarting a managed publisher: an immediate
CLI call must not spawn another daemon while its supervisor is starting.
The delayed healthy Unibus `0.1.7` publication ultimately completed; the catalog
was checked before retrying that immutable version. Its signed manifest reached
the guest and the native `mycelium-update.service` successfully activated it
through the automatic-policy runner. The temporary Unibus manual hold was
removed: Mycelium, Canvas and Unibus automatic updates are enabled again, with
the original minimum-age, rollout and retry gates unchanged. The deliberately
failing `0.1.6` fixture is superseded on the isolated channel. No unrelated local
build/test jobs were paused or stopped to finish this check.
The final settled-policy reboot retained all four recorded identity hashes,
Mycelium `0.1.21`, Canvas `0.1.9`, and Unibus `0.1.7`. All six edge/update units
were active, the timer was enabled, and both automatic-policy runners reported
current with no further activation. Unibus's final activation record had no
error and `verified_service: true`.
Compositor automatic activation remains gated and unrelated cloud assignments
remain manual. This evidence is not a fleet rollout or a Pi 3B+ qualification.

Native binaries retain the existing signed-manifest, digest, immutable-release
and locally authorized service-binding boundaries. This is not an APT backend;
APT and native activation must never both own the same component.

## Dependency admission

Local placement policy can declare exact compatibility requirements:

```json
{"name":"canvas","channel":"fungos-edge-test","requires":{"unibus-router":"0.1.0"}}
```

The dependency must also be assigned on the same node. Reconciliation validates
the graph, selected versions, signatures and every cached payload before new
activation. Providers precede dependents. Missing assignments, cycles, conflicting
requirements, wrong versions and corrupt/incomplete staging fail visibly.
Requirements are operator policy, not remote executable commands or guessed ABI
compatibility. The highest selected channel version must satisfy the requirement;
the updater does not silently choose an older release.

Dependency-linked components are currently explicit-reconcile only. Automatic
filtering must not activate a provider alone while omitting its dependent.
This is ordered, fully staged admission, **not an atomic multi-package transaction**.
Write admission currently permits at most one changed or unhealthy member of a
linked set, using the qualified single-package rollback; multi-member changes
fail before new activation. Whole-set recovery and mixed-version compatibility
still need qualification before enabling simultaneous or automatic linked
updates. Independent packages retain their existing automatic gates.

## Interrupted activation

Before stopping a bound service, activation writes and fsyncs an owner-only
`software/PACKAGE/activation-pending.json`. It records the previous internal
release link and digest, not secrets or commands. Release bytes and pointer
updates are synced. The checkpoint is removed only after native verification,
or after verified restoration following a failed activation.

Daemon startup resumes pending operations on a blocking worker, outside RPC and
gossip. It does not select new releases. Recovery validates the checkpoint and
previous bytes, uses the existing service binding, stops the candidate, restores
the prior link, starts and verifies the previous executable. An interrupted first
install stops the candidate and removes its unverified link instead.
Failed recovery remains checkpointed and is reported in the daemon log; a fresh
read-only reconciliation cannot report it as current. Explicit
`mycelium software reconcile --write` also
retries recovery before selecting new work, even if candidate bytes disappeared.

Manual parity: inspect the pending record and owner service binding; check prior
release integrity; stop the managed unit; restore its internal `current` symlink;
start the unit and perform its application health check; clear the record only
after verification. Prefer the CLI retry to manual edits. Never delete a record
merely to silence a failure.

## Health and tests

The edge profile already uses the correct owner interfaces:

- Unibus `health.sock` performs authenticated schema-2 registration and grant
  checks before replying `READY unibus`; this is not a TCP port-presence check.
- Canvas performs a bounded JSON `inspect` with request-ID and outcome checks.
- Native verification checks that the managed PID owns the listener and executes
  the expected signed binary digest. Silent, oversized, mismatched and redirected
  responses fail existing tests.

On the running edge QEMU, the Unibus probe passed, rejected a temporarily absent
health-only credential while the router stayed active, then passed after restoring
that credential. No credential bytes were printed. All six edge services remained
active. This validates authentication, not delivery of a user media workload.

Agora checks and daemon tests cover dependency ordering/version rejection,
checkpoint integrity, failed recovery retention, first-install recovery and an
actual SIGKILL after the pointer switch. The opt-in
`software::tests::qemu_interrupted_activation_reboot` uses the same production
checkpoint code in a marked disposable disk guest. Its lifecycle is a fixture,
not an application service; it must not be mistaken for live Canvas/Unibus rollback.
Use `fungos-update-safety-proof.service` only with the existing disposable image
builder and qualification guard. It reboots and powers off that guest.

## Qualification, 2026-10-06

Agora `cargo check -p myceliumd --tests` passed. The serial daemon suite passed
96 tests with one explicitly ignored disruptive QEMU test. That test was then
run separately in QEMU/KVM with one CPU, 2 GiB, a fresh persistent ext4 artifact,
no NIC and no fleet identity. The [raw serial log](update-safety-qualification-20261006.log)
contains `FUNGOS_UPDATE_SIGKILL_CHECKPOINTED` on the first boot and
`FUNGOS_UPDATE_REBOOT_RECOVERY_VERIFIED` on the second, followed by a passing
test result and clean poweroff. This is checkpoint/link recovery across reboot,
not a whole-set transaction or a live application rollback proof.

Stripped qualification test executable SHA256:
`287db69cc87391b736739c284c39dedeac7b09c9502e4335f20cfeac650c4ae2`.
QEMU qualification checkpoint source (`software.rs`) SHA256, before the final
multi-member admission guard:
`6cb5a521605238e9e5e9b6f4085f99db1d4bf5b8a314a704ce71f56a92a71bd1`.
Artifacts and the failed first boot are retained on Agora under
`/home/ajmwagar/.cache/fungos-update-safety-qemu`.
The first boot failed before userspace with `mount: not found`; the successful
image uses explicit `/busybox` commands during early init. Its debug test
executable was stripped before image construction. No boot-speed or minimum-RAM
claim is derived from this qualification run.

The isolated source export's committed lockfile contained a stale EdgeOS entry
in the UniFi dependency list. Checks used an offline-regenerated lockfile (only
that entry removed); the user's main worktree lockfile was not replaced.
