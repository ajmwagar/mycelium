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

## Edge

`fungOS-edge` extends base for interactive on-premises systems. Its initial
package policy selects:

- Unibus for authorized application messaging and discovery integration;
- Canvas where a compositor or user-facing surface is requested.

Neither application is unconditional. Headless Unibus nodes and Canvas nodes
are separate derived classes, even when a machine satisfies both.

## Compute

`fungOS-compute` extends base for accelerator-capable workers. Its package
policy may select:

- UMIE when a supported GPU or Metal accelerator is observed;
- Yggdrasil for inference placement and execution;
- Shroud only for nodes explicitly assigned the workload-substrate role.

GPU presence can derive accelerator eligibility, but it cannot derive trust or
the Shroud role. Discovery proves availability; signed policy grants placement.

## Delivery boundary

Fab or another build provider produces immutable artifacts. Mycelium verifies,
gossips, selects, stages, and atomically advances signed versions. Native
systemd or launchd adapters restart and health-check services. Profile changes
therefore reuse one update path and do not introduce per-profile installers.
