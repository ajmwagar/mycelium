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
