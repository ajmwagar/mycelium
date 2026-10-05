# ARM conversion and microVM smoke

Verified 2026-10-05 on DGX Spark (Linux aarch64), reached through Mycelium's
Pris jump-host route. No GPU passthrough, host reimage, or production Shroud
service deployment was performed. Default Pi images remain unchanged.

The Shroud candidate is based on upstream `bb9625f`, locally committed as
`ac7881b` on `fix/fungos-arm-shroudoci` in the isolated worktree
`/private/tmp/fungos-shroud-arm` (not pushed/merged). Changes belong to Shroud (`shroud-p5d`):
native architecture selection, pinned helper images, architecture/digest-separated
helper caches, ELF machine checks, cached OCI OS/architecture checks, ARM
`keep_bootcon console=ttyS0`, and fail-fast read-only root/overlay mounts.
It was cross-built on Agora, not on the Pi or Mac. All 49 shroudoci tests passed.
The final portable executable targets `aarch64-unknown-linux-musl`, is statically
linked, and was exercised natively on Spark. Ring's C objects were built with
Agora's Zig 0.14.1 compiler through a temporary adapter translating the Rust
target triple; the final link used Rust's bundled `rust-lld`, preserving the
Cortex-A53 erratum linker flag. No compiler was installed on the Pi or Spark.
The GNU trial references glibc 2.39 symbols and is not the recommended Pi artifact.

Native Spark conversion produced SquashFS plus initramfs from:

```text
arm64v8/busybox@sha256:d57ca6148df4c262ea31a867c55d257b3a597c71dc63e5b66aae47dc150c73c4
```

An isolated Firecracker 1.16.1 ARM microVM then ran the converted image with
one vCPU, 128 MiB RAM, no network interfaces, no GPU, and a 30-second host
runtime limit. It checked `/etc/passwd` from the converted root filesystem,
printed `FUNGOS_ARM_ROOTFS_OK` and `aarch64`, then exited with status zero.
The host transient unit stopped successfully; no microVM was left running.
The final boot has no root-disk mount warning. Missing `eth0` messages are
expected in this deliberately network-isolated test.

Experimental artifacts retained on Spark under
`/home/fpladmin/.cache/fungos-arm-smoke.UmBUlM`:

| Artifact | SHA-256 |
| --- | --- |
| shroudoci GNU candidate | `615ecb1f08624a59b42109f0f4295aec7cfcb257f033b2247f5b8ed62f3a7cdc` |
| shroudoci static musl candidate | `98ff6f7efcdf6a05d11954dc8b9aac79a2503509de496f0af964a3c3a1b02fdf` |
| rootfs.sqsh | `b37641ab461ac5a66408e4ce172f90d7dab4a4624e1c1df399691c8aa0e9f342` |
| initramfs.cpio (final musl run) | `5c94c1fe7b3b45da879bb0bd88674565f5e51cb7808c54edf22127a827ccb261` |
| upstream Firecracker release archive | `8d0e69f6d6f9a1724551f607f18504052c16c1828ee3d4d7b6e6c73380871e0e` |
| upstream ARM kernel Image 6.1.186 | `a4d2441d2c31116fcfc80c0e955ab3f46e131a3bd6a95a2c69ba66d4a7b6ccde` |

The guest kernel came from Firecracker's official CI object
`firecracker-ci/20260930-a738f18a8db0-0/aarch64/vmlinux-6.1.186`.
Its filename notwithstanding, it is an ARM64 Image, not an x86 ELF kernel.
Upstream downloads used HTTPS; recorded hashes are experimental evidence,
not a claim of production signed-artifact admission. The test used a bounded
root-run transient service, not Firecracker's production jailer setup.

This proves ARM image conversion and direct Firecracker execution on Spark.
It does **not** yet prove Shroud-daemon ARM lifecycle, signed package activation,
Pi KVM availability, networking, GPU passthrough, or production image readiness.
Firecracker requires Linux KVM and a same-architecture guest; fungOS edge
support alone does not imply a board is a verified microVM host.

Installing missing skopeo/umoci dependencies unexpectedly triggered Ubuntu's
needrestart and restarted six resident UMIE services. GPC-1 exposed an obsolete
spec API call and required separate authorized repair (`umie-u4dn`): only the
obsolete `host.cache_budget` field was removed, matching the current UMIE spec.
The original is retained at
`/usr/local/share/umie/specs/gpc1.lua.before-fungos-arm-20261005`.
GPC-1 recovered and returned health status `ok` for Qwen/Qwen3.5-35B-A3B on
loopback port 8102; the other five resident services remained active. Future
tooling installs must set `NEEDRESTART_MODE=l` and explicitly schedule any
service restart after checking the native workload owner.
