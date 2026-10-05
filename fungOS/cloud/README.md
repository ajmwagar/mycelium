# fungOS cloud substrate

`cloud` inherits the same base as edge, adding native workload tools without
Canvas, Unibus, model files or credentials. The build currently produces a
runtime rootfs tarball, **not a bootable DigitalOcean custom image**:

```sh
fungOS/base/scripts/check.sh
fungOS/base/scripts/build.sh amd64 cloud
```

Arm64 package resolution is supported, but that does not prove a working
Firecracker/kernel artifact set on any arm64 machine.

## Application ownership

Shroud owns workload execution, virtual networking, persistence and recovery.
Fab's `fabd` is still a separate binary in `fpl/fab/crates/fabd`; it invokes
Shroud's control socket rather than becoming part of Mycelium. Mycelium owns
identity, access, observations and signed executable delivery. No build
controller, GitHub key, database credential, enrolled identity or model belongs
in the public base image.

The native Shroud unit executes the managed package link and requires actual
KVM and TUN devices. Firecracker and its compatible guest kernel must be
provisioned independently with verified provenance. Create `/etc/shroud/vms`
empty and root-owned. `--no-autostart` prevents staged configuration from
launching workloads before placement is authorized. Keep the unit disabled
until runtime preflight passes. Do not enable automatic Shroud package updates
without a workload-aware drain and recovery contract.

Fab's existing native unit and `/etc/fab/fabd.env` contract are owned by
`shared-infra/projects/beachhead/systemd/fabd.service`. Reuse that integration
after the Shroud runtime and runner image pass a real isolated build; do not
invent another Fab API or bake production credentials into a test image.

## Migration boundary

Beachhead lives in `shared-infra/projects/beachhead`. Its root owns the regional
substrate, VPC, ingress, durable artifact bucket and PostgreSQL. Bob capacity is
already represented in `beachhead/bob.tf`; do not replace that inventory with a
second machine list. Existing resources have destruction protection and some
image changes are intentionally ignored, so changing an image string is not a
migration.

Use a parallel replacement node, verify enrollment/access and an isolated
workload, preserve storage and identities deliberately, then move placement
and ingress with a documented rollback. Do not destroy/reimage existing
Beachhead or Bob nodes as a bootstrap shortcut. Live cutover requires current
inventory, verified backups, workload drains and explicit replacement capacity.
Local QEMU workload proof precedes cloud image import and production cutover.

## Initial staging evidence

On 2026-10-05, Agora built and inspected the amd64 cloud runtime rootfs:
`/home/ajmwagar/.cache/fungos-cloud.80lMDp/out/fungos-cloud-amd64.tar`
(approximately 192 MiB), SHA-256
`dc6696019fe8243104fa25837e9607b816c2ec227a1f3aba5af4a2acdf4a25c3`.
Required base files and native workload executables passed checks in the
assembled rootfs; machine-id is blank. This inherits the experimental pinned
Debian snapshot from January 2025, not a currently patched production release.
Refreshing and assessing the baseline is required before public release or
production migration. There are no enrolled identities or application secrets.

The existing Agora Shroud artifact was signed for the isolated
`fungos-cloud-test` channel and activated in the current fungOS guest:
`7ed370adcf8884214529756084b81a2e2be794cb9edc76bcda713f97764347a0`.
Its loader smoke test and `--check-config` with an empty owned config directory
passed. Metadata arrived through gossip; bytes were manually seeded. This is
host-artifact staging, not a new source build, daemon readiness, or microVM
execution proof. The existing guest exposes `svm` but lacks `/dev/kvm` and the
cloud runtime packages; neither a Shroud daemon nor Fabd was started. The five
existing edge services remain active, and Agora's existing Shroud is untouched.
