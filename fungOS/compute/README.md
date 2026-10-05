# Optional fungOS compute applications

Unibus stays independent of inference and workload execution. UMIE and Shroud
are optional signed executable packages, selected by explicit roles through
[manual policy](software-policy.json). GPU observations never grant workload
placement authority. Do not replace an existing node policy wholesale: merge
the rules into the operator's policy and preview the resulting plan.

The [UMIE experiment unit](qemu/umie.service) executes the package's `current`
link, listens only on loopback and reads a local model-directory setting. It
does not bundle a model, driver, secret or NVIDIA library. Provision those
dependencies separately and install the environment file owner-only. Model
files include compatible weights, tokenizer and model/spec metadata; a weights
file alone is not a ready serving directory.

UMIE's current Linux implementation requires CUDA. A VM without a passed-through
GPU and matching NVIDIA driver/userspace is not an inference node. The device
condition prevents an accidental restart loop; it is not a health predicate.
The unit is staged disabled until the compute substrate is ready. Check
`/health`, `/v1/models` and a real inference request after model load. The current
health response is not a bounded worker-liveness proof suitable for automatic
updates; no automatic native binding is supplied yet.

Shroud already fits the generic `packages publish --name shroud` path. Before
adopting its native unit, establish a Shroud-owned drain and restart/recovery
contract: stopping a workload daemon is not equivalent to restarting a UI.
Mycelium must not implement Shroud scheduling or infer that VM data is disposable.
Manual package staging is not authorization to stop the host's existing daemon.

## Agora assessment (2026-10-05)

Agora runs Shroud, managed agents, deployment/VPC services, Yggdrasil and the
fungOS QEMU experiment. Its RTX 3060 (PCI `0000:2d:00.0`) was using roughly
9.6 GiB, including a live llama-server and video encoding. IOMMU group 27
contains the GPU and its audio function (`0000:2d:00.1`). No devices were
unbound, no workloads drained and no host boot configuration changed.

Before GPU passthrough, choose a downtime window or another GPU; inventory
all group devices, verify VFIO and reset support, preserve recovery access,
then supply the guest driver/CUDA runtime. Group membership alone is not
proof of a working passthrough configuration. Physical PXE/reinstallation is
later than in-place adoption and a verified VM experiment.

## Current experiment state

The QEMU UMIE unit is installed but disabled; Unibus and Canvas's Unibus adapter
remain active. A [temporary GPU handoff](qemu/GPU-HANDOFF.md) successfully loaded
Laya and served three real GPU-backed decision requests alongside the edge
services. The GPU has since been returned to Agora; the guest is back to its
original no-GPU configuration. No automatic GPU allocation policy was introduced.
Current UMIE source was copied to an isolated Agora build snapshot; `cargo check
-p umie-serve --locked` passed and its server tests passed (14 passed, one
hardware/model-specific test ignored). The GNU glibc 2.36 release cross-build
now succeeds with UMIE's opt-in `onnx-dynamic` feature, architecture-specific
OpenSSL headers and explicit `UMIE_CUDA_LIB_DIR`. The downloaded static ONNX
archive needs glibc 2.38; it cannot be made compatible by selecting an older Zig
target. See UMIE's `docs/linux-cross-build.md` for the reproducible build runbook.
ONNX embeddings require a separately provisioned compatible runtime; the default
UMIE build is unchanged. Host UMIE binaries are not silently substituted.

The new executable requires at most glibc 2.35 and dynamically links cuBLAS 12
(plus libc/libm/the loader), without a GNU C++ runtime dependency. Dynamic-mode
tests passed: five embedding tests and fourteen server tests, with two
hardware/model-specific tests ignored. This is not GPU/model readiness evidence.

QEMU loader smoke succeeded with the candidate at `/tmp/umie-cross-build-test`
and private CUDA 12.4 cuBLAS libraries under
`/opt/fungos-compute/cuda-loader-test`; `ldd` resolves every dependency and the
executable returns its normal usage response. These libraries are experiment
dependencies, not part of the public base image. Candidate SHA-256:
`fe3c524204956751dc9f1a075de55cf217d1af19689b98eba2cc3b251221fbdd`.
Signed publication is now confirmed on `fungos-compute-test`; the guest received
the authority-signed manifest through gossip. `releases seed` verified the
uploaded candidate against that manifest, and `software activate umie` installed
version 0.1.0 with the same digest under the managed `current` link. This was
manual byte seeding, not evidence of automatic artifact fetching. The disabled
UMIE service was subsequently started and verified during the temporary handoff,
then stopped before host recovery. It remains disabled after the experiment.

The publication incident exposed an unresponsive local daemon, exhausted Neo
disk space, and a startup ordering bug: saved-device reconnection ran before RPC
acceptance. Reconnection now runs in the background with a 30-second deadline
per device, retaining unreachable devices. Hello and publication client requests
are bounded; a timeout reports unknown outcome and closes the write side to
prevent late-response reuse. Do not blindly retry a timed-out publication: check
the catalog first. Disposable local `/tmp` build copies were removed, not source,
identities or installed packages.

For guest seeding, upload to `/var/lib/mycelium/incoming` (owner-only), not `/tmp`:
the daemon's systemd `PrivateTmp=yes` intentionally hides the SSH session's
temporary directory. Keep the sandbox; do not disable it to copy an artifact.

The compute policy test confirms GPU presence alone selects neither package,
and explicit UMIE/Shroud roles retain manual updates. Shroud host adoption and
drain semantics are still pending; Agora's existing daemon was not replaced.
