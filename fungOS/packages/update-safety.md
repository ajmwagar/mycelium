# Update safety

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
This is ordered, fully staged admission, **not an atomic multi-package transaction**:
an earlier verified package can remain updated if a later member fails. Each
failed activation restores its own prior version. Whole-set recovery and
mixed-version compatibility still need qualification before enabling automatic
linked updates. Independent packages retain their existing automatic gates.

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
95 tests with one explicitly ignored disruptive QEMU test. That test was then
run separately in QEMU/KVM with one CPU, 2 GiB, a fresh persistent ext4 artifact,
no NIC and no fleet identity. The [raw serial log](update-safety-qualification-20261006.log)
contains `FUNGOS_UPDATE_SIGKILL_CHECKPOINTED` on the first boot and
`FUNGOS_UPDATE_REBOOT_RECOVERY_VERIFIED` on the second, followed by a passing
test result and clean poweroff. This is checkpoint/link recovery across reboot,
not a whole-set transaction or a live application rollback proof.

Stripped qualification test executable SHA256:
`287db69cc87391b736739c284c39dedeac7b09c9502e4335f20cfeac650c4ae2`.
Qualified `software.rs` SHA256:
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
