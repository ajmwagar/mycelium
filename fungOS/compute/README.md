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
