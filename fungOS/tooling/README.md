# Optional host tooling

`shroudoci` is an optional development/edge utility, not a service or a grant to
execute workloads. Shroud owns OCI conversion and its existing `rootfs:` artifact
contract. Mycelium distributes the signed executable using its existing package
authority; no second signer, updater, or image schema is introduced.

Base and all default edge/Pi package sets are unchanged. To add native conversion
tools to an amd64 image, run from the repository root on a Linux builder:

```sh
CAPABILITY_OVERLAY="$PWD/fungOS/tooling/shroudoci.capabilities" \
  fungOS/base/scripts/build.sh amd64 edge
```

The overlay adds skopeo, umoci, squashfs-tools and cpio, not Docker or a compiler.
It can also be used with base, headless-edge or cloud. Build output remains a
rootfs archive, not a bootable disk image. Use a fresh work directory per build.

Use `software-policy.json` as an opt-in package policy (or merge its rule into the
host's existing policy). Only Linux x86_64 peers explicitly carrying
`role.shroudoci` are selected. Publish a compatible `shroudoci` executable to
`fungos-tooling-test` with the existing authorized release signer, verify its
digest, then manually activate it through Mycelium. This slice does not publish
an artifact or enable unattended utility updates. No service health check is
invented for a CLI: validate a pinned OCI conversion before approving a release.

ARM conversion is deliberately not selected yet: current Shroud code fetches
`amd64/busybox:musl` for its initramfs helper. Fix architecture selection and pin
that helper upstream before enabling Pi/arm64 conversion. The executable's
signature does not authenticate arbitrary downloaded OCI content; pin source
digests and verify converted manifests through Shroud's artifact admission path.
Registry credentials stay local and must not be embedded in images or gossip.

Workload execution, service lifecycle and deployment remain independently
authorized. Installing this utility starts no Shroud daemon and enrolls no
workload guest in Mycelium.
