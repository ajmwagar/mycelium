# fungOS profiles

Profiles are desired capability sets, not independently maintained operating
systems. Every profile extends the same minimal base and uses Mycelium's signed,
content-addressed package policy for optional first-party applications.
Service lifecycle remains owned by an explicit native adapter, not Mycelium.

## Base

`fungOS-base` contains only the operating substrate required to remain
reachable and supportable:

- hardware discovery and networking;
- OpenSSH and trust roots;
- Mycelium identity, access, health, and signed self-update;
- the provider-neutral first-contact and update-verification interfaces.

No media, inference, workload, or product application belongs in the base.

Development and capable edge hosts can opt into [Shroud OCI conversion
tooling](tooling/README.md) independently of workload execution. Its native
dependency overlay and signed executable policy do not change default images.

## Edge

`fungOS-edge` extends base for interactive on-premises systems. Its initial
package policy selects:

- Unibus for authorized application messaging and discovery integration;
- Canvas where a compositor or user-facing surface is requested.

Neither application is unconditional. Headless Unibus nodes and Canvas nodes
are separate derived classes, even when a machine satisfies both.

The build accepts `edge` and `headless-edge` for both `amd64` and `arm64`:

```sh
fungOS/base/scripts/build.sh amd64 edge
fungOS/base/scripts/build.sh arm64 edge
fungOS/base/scripts/build.sh amd64 headless-edge
fungOS/base/scripts/build.sh arm64 headless-edge
```

`edge` adds the native runtime dependencies for `canvas-linux` (the Wayland/KMS
compositor) and `canvas` (its Wayland client), plus Unibus. `headless-edge`
selects Unibus without a graphical session, Canvas, Xorg or Weston. Both inherit
the base declaration rather than duplicate its package list. First-party
executables still come from authorized signed package releases, not Debian apt
or embedded credentials; these commands produce runtime rootfs tarballs, not
fully provisioned bootable images.

Architecture is separate from board support: `arm64` is the Pi 64-bit userspace
target, including Pi 3B+, but boot firmware, a matching board kernel and its
modules must be supplied by Genesis's board-specific boot path. An arm64
tarball alone is not a verified Pi SD-card image. The existing QEMU display
module/unit is amd64-test-specific and must not be installed on a Pi.

## Compute

`fungOS-compute` extends base for accelerator-capable workers. Its package
policy may select:

- UMIE when a supported GPU or Metal accelerator is observed;
- Yggdrasil for inference placement and execution;
- Shroud only for nodes explicitly assigned the workload-substrate role.

GPU presence can derive accelerator eligibility, but it cannot derive trust or
the Shroud role. Discovery proves availability; signed policy grants placement.

## Cloud

`fungOS-cloud` extends base with native workload runtime dependencies for Shroud
and an optional separate Fab build controller. It does not inherit edge display
or messaging packages and does not require a GPU. See the [cloud substrate
boundary](cloud/README.md) for signed applications, KVM preflight and migration.

```sh
fungOS/base/scripts/build.sh amd64 cloud
```

This currently assembles a runtime rootfs, not a bootable DigitalOcean image.
Beachhead and Bob remain owned by shared-infra's existing IaC resources; a
cloud profile is not permission to destroy or reimage them.

## Delivery boundary

Fab or another build provider produces immutable artifacts. Mycelium verifies,
gossips, selects, stages, and atomically advances signed versions. Native
systemd or launchd adapters restart and health-check services. Profile changes
therefore reuse one update path and do not introduce per-profile installers.

## Assigning a runtime profile to an enrolled Linux node

The CLI composes existing software placement and SSH reconciliation; it does not
convert an installed base image or install missing Debian runtime dependencies.
Build/install those dependencies through the image's normal provisioning path.
Changing a runtime profile does not uninstall deselected packages or stop their
services. `profile.edge` is descriptive discovery metadata, never an access role.

An intent names the stable peer ID, runtime profile, optional hostname, existing
software-policy representation, and whether to reconcile already-configured SSH
host policy. For example, create the local intent from a reviewed package policy:

```sh
export MYCELIUM_HOME=/var/lib/mycelium
node_id=$(sudo --preserve-env=MYCELIUM_HOME mycelium node status --json | jq -r '.node.hello.node_id')
jq --arg id "$node_id" '{
  node_id: $id,
  profile: "edge",
  hostname: "edge-lab-01",
  software_policy: .,
  reconcile_ssh: false
}' reviewed-software-policy.json > node-intent.json

sudo --preserve-env=MYCELIUM_HOME mycelium node plan node-intent.json --json > node-plan.json
sudo --preserve-env=MYCELIUM_HOME mycelium node apply --plan node-plan.json --dry-run --json
sudo --preserve-env=MYCELIUM_HOME mycelium node apply --plan node-plan.json --write --json
sudo --preserve-env=MYCELIUM_HOME mycelium node status --json
```

Use `node.PEER_ID` in software selectors instead of `host.OLD_HOSTNAME` when
renaming. Plans project the requested hostname/profile into existing observed
facts and display the selected package versions/digests. An old-hostname policy
that selects nothing fails loudly. The planner pins peer identity, current
hostname/policy/intent, selected manifests and optional SSH grant/CA view into
the existing content-addressed `StateChangePlan`. Changed preconditions require
a fresh plan. Root and explicit `--write` are required for application. Missing
compatible manifests or cached artifacts block before mutation.

Apply saves desired state, sets the static/transient hostname with Linux's
`hostnamectl`, refreshes signed discovery without restarting the daemon, and
calls the existing software and optional SSH reconcilers. The peer key,
transport certificates and machine-id stay intact. This does not change DNS,
certificate SANs, addresses, VLANs, images or reboot policy. Repeating a freshly
planned healthy intent leaves application processes running. The normal native
update timer still owns later automatic software repair; hostname and SSH
changes are not smuggled into that timer.

For `reconcile_ssh: true`, first configure the existing host policy with
`mycelium access ssh host-policy set --role ROLE --ca-public /absolute/user_ca.pub --write`.
Signed grants/revocations must have converged from an already-trusted authority.
The node planner does not create grants, accept a new CA, grant sudo or store
passwords. The existing SSH reconciler owns account creation, principals, KRL
validation and trust-file rollback. Its dedicated timer remains available via
`mycelium access ssh host-policy install-timer --write`.

The common execution receipt records success or failure under the node's
Mycelium state. This is **not** a cross-domain atomic transaction: desired policy
can persist and a hostname can change before a later package/access operation
fails. Inspect the receipt and live state, fix the reported prerequisite, then
generate a fresh plan. Per-package rollback remains independently verified.
Do not infer successful profile reconciliation from metadata alone. Concurrent
independent software publishers/operators are not serialized by the local node
write lock; quiesce those when applying a reviewed lifecycle change.

For manual recovery, the same operations are independently available: software
policy set/reconcile, `hostnamectl`, node observation refresh through apply, and
SSH host-policy reconcile. Neither Fab, Unibus nor a central controller is
required. This first adapter supports Linux/systemd; Darwin remains read-only
for node status until it has its own hostname/service adapter.

### QEMU verification, 2026-10-06

Clean-source type checking and 142 tests passed on Agora (54 CLI, 88 daemon).
Signed Mycelium `0.1.13` was published on `fungos-qemu-test`, received through
manifest gossip, explicitly byte-seeded and installed through signed self-update.
Installed SHA-256:
`f537b400ec078b48d205a2859257c43a0b0a664928d781228d5e834c43063c22`.

The persistent guest was renamed from `fungos-qemu-01` to
`fungos-edge-qemu-01` and assigned `edge`. Its existing edge and manual cloud
test packages remained current after replacing hostname selectors with the
stable peer-ID selector. Dry-run left hostname and desired-state files untouched;
apply produced a succeeded common receipt. Neo received the new hostname and
`profile.edge` through signed gossip, under the same node identity.

The old plan was correctly rejected after apply changed its preconditions.
A freshly planned repeat retained Unibus PID 22089 and Canvas PID 253. Restarting
only Mycelium retained the profile and hostname; machine-id and peer-key hashes
were unchanged. The transport certificate hash also remained unchanged across
that daemon restart. All five edge units and the update timer remained active.
No VM reboot, networking, DNS, account or authority changes were made.

The SSH-enabled intent was rejected before mutation because this guest has no
SSH host policy. Read-only assessment also found no configured access-authority
keys or converged grants. Existing SSH account/grant tests pass, but **positive
live SSH reconciliation is not yet verified on this guest**. Configure its
existing fleet SSH authority and authorized grants explicitly before enabling
that part of the intent; profile assignment does not mint them.
