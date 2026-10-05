# Temporary GPU passthrough experiment

Verified on Agora on 2026-10-05. This is an operator-run experiment, not an
automatic hardware allocation policy or a production-ready driver installer.
The signed UMIE package and digest are recorded in the [compute README](../README.md).

## Observed result

Agora's RTX 3060 and HDMI audio function, `0000:2d:00.0` and `0000:2d:00.1`,
were the only devices in IOMMU group 27. Both were attached to QEMU through
`vfio-pci`. The existing persistent fungOS guest booted with 6 GiB RAM instead
of 2 GiB, keeping its virtual VGA display for the Canvas compositor.

Guest kernel `7.0.0-34-generic` matched the host modules. NVIDIA open driver
595.91.07 recognized the passed-through GPU and its 12 GiB VRAM. Private
experiment dependencies included matching GSP firmware, driver/JIT libraries,
CUDA 12.4 cuBLAS and NVRTC, and the existing Laya model directory. Model and
kernel-module hashes matched their host sources before the drain.

The signed UMIE executable started through `umie.service` and loaded Laya.
Its GPU allocation grew from approximately 948 MiB to 1088 MiB over three
requests. A temporary SSH tunnel to the guest's loopback listener exposed
`/health`, `/v1/models`, `/v1/systemone` and `/metrics` for verification.

| Input | Selected answer | Selected probability |
| --- | --- | --- |
| Turn on the lights | on | 0.9543 |
| Turn off the lights | off | 0.9744 |
| What time is it? | none | 0.8154 |

First-request worker turnaround was approximately 104 ms. This includes queue
and execution time, not an isolated GPU-kernel benchmark. These were bounded
decision requests only: no lighting device was commanded. Mycelium, Unibus,
Canvas compositor, Canvas app and Canvas adapter remained active in the guest.

The GPU was returned to Agora after the test. Host inference was verified on
CUDA again (approximately 9.3 GiB VRAM, `/health` returned `ok`), the NVENC QEMU
stream encoder restarted, and the GDM greeter returned. Surf-worker's service
and loopback listener restarted; existing browser sessions were not verified
to survive the worker restart. The guest returned to its original 2 GiB/no-GPU
configuration; its five edge services recovered. UMIE remains disabled/stopped,
with the signed executable, model and private driver dependencies retained.

## Manual sequence and safety gates

1. Re-inventory the GPU, all IOMMU-group devices, reset support and current
   `/dev/nvidia*` users. Do not assume this group's membership or service list
   is permanent. Confirm an independent SSH recovery path and sudo access.
2. Prepare the guest before downtime: compatible signed executable, matching
   kernel modules and firmware, runtime/JIT libraries, model/tokenizer/config,
   memory headroom, and a disabled loopback-only native UMIE unit. Validate
   hashes and loader compatibility. Dependencies are private test provisioning,
   not new redistributable contents of the public base image.
3. Record native unit states and the original QEMU command. Prepare a root-owned
   recovery script and arm a host `systemd-run --on-active=15m` timer **before**
   draining. Recovery must work with either already-bound or unbound devices.
   Its responsibilities are stopping the test VM, clearing only these devices'
   `driver_override`, reattaching original drivers, removing the volatile QEMU
   override, and restoring previously running native services.
4. Stop the inference worker and GPU encoders through their native units;
   stop the display manager if it holds the GPU. In this test these were user
   `ornith-llama-cpp`/`unibus-qemu` and system `surf-worker`/`gdm`. Verify no GPU
   users remain; never unbind a busy GPU. Cleanly power off the guest and stop
   its host QEMU unit before changing driver ownership.
5. Set both exact PCI functions' `driver_override` to `vfio-pci`; unload unused
   NVIDIA modules, unbind remaining original drivers, and probe both functions.
   Confirm both bindings. Grant only the QEMU user temporary access to that VFIO
   group. Use a volatile `/run/systemd/system/...service.d` override, sufficient
   guest memory, `LimitMEMLOCK=infinity`, and both `-device vfio-pci,host=...`
   arguments. Do not modify bootloader settings or blacklist drivers permanently.
6. Start QEMU and verify the guest sees the physical GPU. Load its matching
   `nvidia` and `nvidia-uvm` modules and initialize device nodes with native
   NVIDIA tools. Start UMIE only after the GPU is usable. Require a real request,
   correct response, metrics and a GPU-backed process—not just an open port.
7. Stop UMIE, flush the guest filesystem and shut it down cleanly. Run recovery
   while the watchdog is still armed. Initialize host UVM, modeset/DRM and
   device nodes **before** restarting clients; otherwise inference may silently
   fall back to CPU. Verify host inference, encoder, display and guest edge
   recovery separately. Remove temporary overrides and cancel the watchdog
   only after ownership and recovery are verified.

The one-off recovery files are retained on Agora under
`~/.cache/fungos-gpu-handoff`; the root-owned watchdog copy lives under
`/run/fungos-gpu-handoff`. They contain this machine's paths and are evidence,
not a generic fleet command. Re-inventory and revalidate before another run.

## Pitfalls discovered

- Cudarc's CUDA-13 build searched unversioned `libnvrtc.so` but not the installed
  `libnvrtc.so.12`. A normal unversioned link to the installed NVRTC library fixed
  discovery. No fake `.so.13` alias was created. Actual model load and requests
  validated the CUDA 12.4 compiler/595 driver combination for this Laya workload;
  this does not prove all CUDA-13-specific workloads compatible.
- Ubuntu's NVIDIA udev remove hooks kept unloading display modules after the
  rebind. A temporary runtime copy of `71-nvidia.rules` omitted only unload hooks
  while the event queue settled. Then modeset/DRM and GDM were restored, that
  runtime override was removed, normal rules reloaded and the queue settled
  again. No vendor rule was edited permanently. Do not blindly declare recovery
  because `gdm.service` is active: verify a registered greeter/display session.
- Device-node initialization after starting clients was too late. The first
  host inference restart chose CPU; restarting after NVIDIA initialization
  restored its CUDA allocation. Native service activity alone is insufficient
  recovery evidence.
