# Update safety

## Managed startup, status and reboot recovery, 2026-10-07

Mycelium now recognizes its installed systemd or launchd service by the exact
state directory. Implicit CLI startup waits for the supervisor rather than
starting a competing detached daemon. Explicit detached startup refuses a
managed home and directs the operator to its installed service. Standalone
publisher/test homes retain autostart.

`software status` derives live observations from the installed policy.
Downloading includes durable partial-byte progress. Waiting explains manual
activation, initial installation, missing native binding, dependency linkage,
or cache-age/rollout/retry gates. Status and automatic activation share the
same eligibility deadline calculation. A previous rollback is retained in
`last_activation`, separately from present health. Old receipts default to
no asserted rollback; malformed receipts fail visibly.

Activation outcome writes are synced while holding the package lock, before
clearing a successfully completed or rolled-back checkpoint. Recovery likewise
persists its receipt before clearing the checkpoint. Artifact partial-file
creation and final promotion sync their directory, and chunk bounds reject
integer overflow.

The disposable, no-NIC QEMU qualification on Agora interrupts activation with
SIGKILL after switching the current link, then reboots its persistent disk.
It requires the guarded DMI identity, runtime marker and exact proof directory.
A changed Linux boot ID proves an actual reboot. The second boot resumes the
persisted partial download, verifies its complete digest, restores the previous
release, verifies the lifecycle fixture, and checks the durable rollback receipt
before powering off. This is a production persistence/recovery test with a
lifecycle fixture, not proof of a real application health check, network download
session, whole-set rollback, published image or fleet deployment.

Manual runbook: build the musl daemon test executable on Agora; install it into
a clone of the disposable proof disk; boot that clone without a network adapter
using the proof unit and marked DMI identity; confirm the SIGKILL, download-resume
and recovery markers on opposite sides of a reboot; then mount the powered-off
disk read-only and inspect the previous current link, rollback receipt and absent
checkpoint. Keep the original disk and edge/TV guests untouched.

Final qualification evidence on Agora:

- `fungos-update-safety-final-20261007.service`: inactive, result `success`.
- Markers: `FUNGOS_UPDATE_SIGKILL_CHECKPOINTED`,
  `FUNGOS_DOWNLOAD_REBOOT_RESUME_VERIFIED`,
  `FUNGOS_UPDATE_REBOOT_RECOVERY_VERIFIED`; guest test: 1 passed.
- Restored link: `releases/1.0.0`; receipt: `rolled_back: true`,
  `verified_service: true`; pending checkpoint absent.
- Console: `/home/ajmwagar/.cache/fungos-update-safety-20261007/console-final.log`,
  SHA-256 `04bdbc197e4ed07b12bc8ae08d560e52536d41cb258c29a1cbb18dc146d294ee`.
- Musl test executable SHA-256:
  `c99f696152076189d791abffd1a6bd1d417997566d2ff243707774f50980a51a`.
- Agora: 107 daemon tests passed, 2 deliberately ignored fixtures; 59 CLI
  tests passed. Test processes require cache-local `TMPDIR`: the initial musl
  test run hit Agora's existing `/tmp` quota; the correctly scoped rerun passed.

These artifacts are private qualification evidence, not published releases.

## Rebuilt runtime boot qualification, 2026-10-07

The rebuilt edge runtime (`0ff4db1c182e47a06ed812b09e10b1235db26af9fb7f8979590ded84696cec32`)
booted its own previously unused root disk as `fungos-edge-rebuilt-01`.
`xcursor-themes 1.0.5-1` was already installed; no package repair was needed.
The one-use claim generated a distinct peer identity, and stable node-ID policy
selected the same four signed edge packages. Their artifacts downloaded through
the authenticated temporary cache peer; native activation verified Canvas and
Unibus readiness, and the compositor reported active DRM output on card0.

Interactive provisioning exposed a second startup race: a CLI called just after
systemd restart could autostart an unsupervised daemon first. The home lock
prevented corruption, but then rejected the supervised process. The fungOS
wrapper now defaults to `MYCELIUM_NO_AUTOSTART=1` once enrolled; standalone
Mycelium CLI behavior is unchanged. The exact stray guest process was removed,
and systemd recovered. A live regression stopped the supervised guest service,
confirmed the CLI failed without spawning any daemon, then restarted it.
The wrapper patch was applied to this guest after its first boot; this is not
an assertion that the earlier initrd already contained that fix.

After shutdown, the claim media and temporary cache seed were removed and the
cache peer stopped. Restarting the persistent guest retained all four identity
hashes; Mycelium, Canvas, Unibus, compositor, adapter and update timer were active,
and all package observations were current. Boot ID changed from
`6fbc87e6-3a41-4c68-8a25-4d592375c7d6` to
`51ae1b32-5fb6-4f5c-84ca-09db54be8535`.
A VNC capture showed the compositor background and cursor, not a populated
desktop. No fleet rollout, physical installer, display-seat hardening or Discord
deployment is implied by this qualification.
The rebuilt image's existing `0.1.24` bootstrap executable was locally seeded
against its trusted signed manifest and explicitly activated, establishing the
first signed update record. Automatic policy is enabled on the guest-only
channel with the same age/rollout gates. This is not another fresh self-update
download proof; the preceding clean guest qualified that separately.

## Clean edge boot and peer download, 2026-10-07

A separate QEMU guest, `fungos-edge-clean-01`, booted a new empty 8 GiB root
disk on Agora. The tracked base/edge overlays were applied to a verified runtime
archive; no live guest filesystem, application artifacts or enrolled identity
was cloned. A private one-use claim disk enrolled the guest in `wagar-house`.
The claim was consumed, the disk detached and its plaintext claim files removed.

The empty application cache fetched Canvas, Canvas Linux, Canvas edge adapter
and Unibus router through an authenticated peer, with the existing release
authority, signatures and byte hashes unchanged. Initial activation was explicit:
Canvas `0.1.6`, Canvas Linux `0.1.1`, Canvas edge `0.1.0` and Unibus `0.1.1`.
Canvas and Unibus passed their native PID-bound health checks. This qualifies
fresh application downloading, rather than another activation of preseeded bytes.

Neo's loaded publisher timed out during TLS setup. An attempted tunnel to the
older QEMU peer was rejected because its certificate had no address SAN; no TLS
verification was bypassed. A temporary cache peer on Agora was issued its own
certificate with the correct address SAN and supplied trusted cached artifacts.
Neither the original QEMU guest nor Agora's running fleet daemon was restarted.
The enrollment installer rewrote Agora's user unit while installing the
temporary home; its original managed-home unit was immediately restored before
daemon reload, and the running fleet PID was preserved.

The verified runtime archive predates the tracked `xcursor-themes` addition.
The first compositor start failed visibly, and Canvas activation was rejected.
Installing that package from the pinned Debian snapshot and selecting
`whiteglass` corrected the guest. Image construction now rejects a display
overlay whose configured cursor is absent. This guest is therefore a qualified
runtime plus an explicit package correction, not proof that the older archive
alone is boot-ready. Rebuild the tracked edge profile before distributing it.

After power-off and restart without the claim disk, all four identity hashes
(peer key, enrollment certificate, machine ID and SSH host key) matched, all
five edge/peer units and the update timer were active, and native reconciliation
reported all four applications current. Boot IDs changed from
`f434e2c7-2871-4623-b486-7a53649882c1` to
`9ceefbde-fbd6-47ec-b3ef-f881cd977f74`.
VNC capture confirmed framebuffer delivery but showed an empty compositor
background, not a populated desktop or a visual application acceptance test.

The daemon now takes a kernel file lock on its state directory before inspecting
or removing its socket. Competing owners fail; independent homes remain allowed;
crash releases the lock without unlinking the lock file. Agora passed daemon and
CLI tests, including a real subprocess crash/reacquire regression, and produced
the musl release binary. Claim-envelope checks reject missing/duplicate claims,
protect the envelope with mode `0600` and refuse an existing output. The display
runtime regression proves rejection before any root image or initrd is created.

The clean guest fetched Mycelium `0.1.22` through that peer and performed its
required first explicit signed bootstrap activation. Installed SHA-256:
`7c16d9990baac8e471cf8014c4ad79ec8360843e41eb36ee768917f3d4a7109e`.
A live competing `_serve` invocation was rejected by the new lock while the
systemd PID and socket inode remained unchanged; all identity hashes and native
edge services remained healthy. This is not a claim that first enrollment
bypasses the existing bootstrap authorization gate.

Next, the automatic-policy runner fetched and activated `0.1.24` after the
unchanged 60-second age gate and deterministic five-minute rollout window.
Its SHA-256 is
`1c0f784fae8b7bf5648edc41968f1693d192477504d0bf199a4bff2524fb14fb`.
This payload is the same tested build stripped on Agora, not new application
features; its different bytes exercised fresh peer download and replacement.
An intermediate `0.1.23` manifest contains the unstripped `0.1.22` bytes and
was not activated. The first automatic invocation staged the downloaded
candidate; later invocations respected the gate, then activated it without
`update apply`. This qualifies the policy runner, not timer-triggered activation.

The cache peer was stopped and its temporary seed removed. A further reboot
retained `0.1.24`, all four recorded identity hashes, current application health
and the active update timer (boot ID
`d81b53f1-9314-41c7-bcfc-66b61af8df0f`). A fresh tracked `amd64 edge` runtime
archive was also rebuilt successfully on Agora, including the missing cursor.
The newly rebuilt archive is separate from the already-qualified corrected
guest root; do not describe it as separately boot-tested.
Its rebuilt initrd and empty root image also completed image construction with
the new dependency guard. These are private qualification artifacts, not a
published release image.

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
