# Shroud boot profiling

This Rust client invokes the existing `shroud.control.v1` Unix API for the
isolated `fungos-smoke` fixture. Shroud owns VM lifecycle, images and networking;
the profiler observes ACKs and the inner guest's execution marker. No new
daemon, image format, or Mycelium inside workload microVMs.

## Repeat

Build on Agora, not on a Pi or Neo:

```sh
cargo check --locked --manifest-path fungOS/cloud/boot-profile/Cargo.toml
cargo test --locked --manifest-path fungOS/cloud/boot-profile/Cargo.toml
cargo build --locked --release --target x86_64-unknown-linux-musl \
  --manifest-path fungOS/cloud/boot-profile/Cargo.toml
```

Copy the binary to the disposable guest through the authenticated Agora SSH
forward. First inspect the [existing fixture setup](../qemu/README.md): one
vCPU, 128 MiB, health disabled, no autostart or published ports. Quiesce other
operators of this fixture. Run there as root, using a fresh output filename:

```sh
sudo ./fungos-boot-profile --write --iterations 5 > boot-profile.json
systemd-analyze time
systemd-analyze critical-chain shroud.service
curl -fsS http://127.0.0.1:9108/metrics
```

The profiler only accepts 1–20 iterations and never starts other VMs. It refuses
to interrupt an already-running fixture. Each acknowledged start is followed
by stop and a stopped-state check, including if marker observation fails.
An unacknowledged start leaves ownership/state uncertain: it fails loudly
instead of blindly stopping a possibly independently started VM. Inspect and
clean up through the existing runbook if necessary.

The current Shroud start path truncates the serial log before starting
Firecracker and acknowledging the request. The client reads only after that
ACK to exclude earlier markers; validate this behavior before profiling another
implementation. Responses/log reads are bounded to 1 MiB, with 30-second
socket timeouts and marker deadline. Observation is a 10-ms-sampled upper bound;
guest execution preceding the ACK cannot be resolved more finely here.

Start ACK means Firecracker started, **not workload readiness**. The marker
proves BusyBox entrypoint execution. Its health-disabled `ready` status does
not prove application readiness; use a real service's health endpoint for that.

## Baseline, 2026-10-06

[Raw five-sample results](baseline-20261006.json) came from Agora's nested KVM
guest `fungos-edge-qemu-01`: Ryzen 5 3600, host kernel `7.0.0-34-generic`,
approximately 2 GiB host RAM. These are fresh microVM boots with **uncontrolled
host caches** and already prepared local artifacts—not cold-cache, OCI-pull,
or bare-metal results. No host reboot, global cache eviction or GPU handoff.

| Measurement | Observed |
| --- | --- |
| Start request → Shroud ACK | 219–233 ms |
| Start request → guest execution marker | 1.321–1.442 s; median 1.417 s |
| Stop request → ACK | 33–52 ms |
| Last host boot: kernel + userspace | 1.496 + 2.371 = 3.867 s |
| Host network-online critical-chain wait | 1.960 s |

The JSON's nearest-rank p95 is the maximum of only five samples, not a production
tail-latency claim. Shroud counters independently confirmed five starts/stops;
running VM count returned to zero. All six host application/management units
remained active. Host figures describe the existing last boot, not five reboots.
The last inner kernel reached `/init` at guest-relative 0.859 s; that clock is
distinct from request timing and must not be silently subtracted from it.

Current Shroud SHA-256:
`71a9e95fdc085d755a02a3d922968bd205c3b1073c971fb254a295c520f86762`.
Firecracker, inner kernel, BusyBox rootfs and initramfs digests matched the
[existing recorded artifact provenance](../qemu/README.md).

Next compare these artifacts on direct KVM versus nested KVM, then evaluate
a deliberately smaller supported guest kernel and real service readiness.
Audit dependencies before changing host network-online semantics; removing
the wait merely to improve a number does not improve readiness.

## Console verbosity comparison, 2026-10-06

ShroudOCI hardcoded `debug` in the guest kernel command line. The attached
[upstream patch](shroud-guest-loglevel.patch), against Shroud `15c05fa`, defaults
to `loglevel=5` and accepts `SHROUD_GUEST_KERNEL_LOG_LEVEL=debug` to restore the
exact previous behavior, or a single digit 0–7. It preserves serial access,
panic/reboot behavior and all security settings. Level 5 prints warnings and
more severe messages; this is not disabling the console.

Four consecutive ten-boot batches used the same candidate binary and prepared
fixture, changing only verbosity:

| Batch | Verbosity | Median request → execution | Range |
| --- | --- | --- | --- |
| [A](boot-console-debug-a.json) | debug | 1.580 s | 1.482–1.695 s |
| [B](boot-console-normal-b.json) | normal | 1.111 s | 1.075–1.201 s |
| [C](boot-console-debug-c.json) | debug | 1.860 s | 1.593–2.290 s |
| [D](boot-console-normal-d.json) | normal | 1.156 s | 1.046–1.417 s |

Table medians average the two central samples; the raw harness JSON uses
nearest rank instead. A→B improved about 30%; C→D about 38%. Shared host load
was uncontrolled and increased during C (load average 11, concurrent compiler
and other VMs), so these are encouraging observations, not an isolated causal
estimate or fleet latency guarantee. All 40 boots completed and the fixture
was stopped after each batch. The baseline above used an older Shroud build
and is not the matched comparison. Representative serial output shrank from
21,471 bytes in debug mode to 3,780 bytes in normal mode.

Build verification on Agora: locked `cargo check -p shroud -p shroudoci`,
75 Shroud tests and 47 ShroudOCI tests passed; release musl build succeeded.
Use a writable `TMPDIR` beneath the build user's cache if `/tmp` is quota-full.
The patch remains an upstream submission artifact, not an upstream merged change.

Candidate Shroud SHA-256:
`e8cbb9ac83bd9e4dacf1660e404f5c25e86ba20fd93cbdc48047e6bbc481eafa`.
It was signed using the existing package authority as version `0.1.2`, channel
`fungos-cloud-test`, target `x86_64-unknown-linux-musl`, seeded through
`mycelium releases seed`, and installed only in this disposable guest using
`mycelium software activate shroud`. Native Unix-JSON service readiness passed;
the previous `0.1.1` release remains available for rollback. No fleet rollout.

To repeat, set a temporary Shroud systemd service drop-in with
`Environment=SHROUD_GUEST_KERNEL_LOG_LEVEL=debug`, reload and restart only after
confirming no workloads are running. Wait for the existing control API's
successful `list` response before invoking the profiler. Repeat with level `5`,
then remove only that temporary drop-in and restart to restore the default.
Do not interpret a connection-refused startup race as a measured boot failure.
The temporary override was removed after this experiment.

## Normal-mode readiness polling comparison

The next [small Shroud patch](shroud-readiness-poll.patch) changes API socket
polling from 100 ms to 10 ms, retaining the metadata readiness check, socket
permissions and ten-second deadline. It does not poll continuously or change
the guest kernel command line. This patch layers on the console patch above.

| Batch | Socket poll | Median request → execution | Median start ACK |
| --- | --- | --- | --- |
| [A](boot-poll-100ms-a.json) | 100 ms | 1.021 s | 202 ms |
| [B](boot-poll-10ms-b.json) | 10 ms | 0.947 s | 123 ms |
| [C](boot-poll-10ms-c.json) | 10 ms | 0.944 s | 124 ms |

These conventional medians show approximately 7% less request-to-execution
latency and 39% less start-ACK latency. All thirty starts/stops passed. Both
versions use normal logging and identical prepared artifacts; caches and host
load remain uncontrolled. This is A/B/B, not a randomized or interleaved trial.
Theme captures/builds were paused and existing display processes stayed running.
Do not compare this quieter-host baseline directly to earlier batches.

Representative raw Firecracker logs corroborate the mechanism: socket bind to
first configuration request was [109 ms before](boot-poll-100ms-a.log) and
[18 ms after](boot-poll-10ms-b.log). The 10-ms observation sampling resolution
and request-to-ACK semantics remain those of the existing profiler.

All 75 Shroud tests passed after locked check; release musl build completed on
Agora. The signed test-channel version `0.1.3` has SHA-256
`12e5984c949be1b8944ccba0de69fdfb43101dd9ed57680640e93e5491b28120`.
It was seeded and activated through existing Mycelium package workflows only
on `fungos-edge-qemu-01`; native service readiness verified and all six host
application/management services remained active. Prior releases are retained.
Shroud's source patches are not upstream merged; no production deployment.

Most remaining latency is after the start ACK. Next measure a supported
microVM-specific kernel against this exact baseline and validate application
health; do not disable warnings, mitigations or readiness to improve a score.
