# Optional host tooling

`shroudoci` is an optional development/edge utility, not a service or a grant to
execute workloads. Shroud owns OCI conversion and its existing `rootfs:` artifact
contract. Mycelium distributes the signed executable using its existing package
authority; no second signer, updater, or image schema is introduced.

Base and all default edge/Pi package sets are unchanged. To add native conversion
tools to an amd64 image, run from the repository root on a Linux builder
(substitute `arm64` for an ARM image):

```sh
CAPABILITY_OVERLAY="$PWD/fungOS/tooling/shroudoci.capabilities" \
  fungOS/base/scripts/build.sh amd64 edge
```

The overlay adds skopeo, umoci, squashfs-tools, cpio and sudo, not Docker or a compiler.
Current Shroud conversion creates initramfs device nodes with sudo; this requires
an explicitly authorized builder/root context. Merely installing sudo or assigning
the tooling role does not grant privileges or install a sudoers rule.
It can also be used with base, headless-edge or cloud. Build output remains a
rootfs archive, not a bootable disk image. Use a fresh work directory per build.

Use `software-policy.json` as an opt-in package policy (or merge its rule into the
host's existing policy). Only Linux peers explicitly carrying
`role.shroudoci` are selected. Architecture compatibility remains owned by the
signed release target resolver, not a second list in this policy. Publish a compatible `shroudoci` executable to
`fungos-tooling-test` with the existing authorized release signer, verify its
digest, then manually activate it through Mycelium. This slice does not publish
an artifact or enable unattended utility updates. No service health check is
invented for a CLI: validate a pinned OCI conversion before approving a release.

ARM conversion requires Shroud's architecture-aware helper patch; the older
binary fetches an amd64 helper and must not be published for arm64. The patched
candidate was cross-built on Agora and exercised on DGX Spark; see the
[ARM smoke evidence](arm-smoke.md). This is experimental until that Shroud
change lands and compatible signed releases are published. The executable's
signature does not authenticate arbitrary downloaded OCI content; pin source
digests and verify converted manifests through Shroud's artifact admission path.
Registry credentials stay local and must not be embedded in images or gossip.

Workload execution, service lifecycle and deployment remain independently
authorized. Installing this utility starts no Shroud daemon and enrolls no
workload guest in Mycelium.
