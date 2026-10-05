# FPL ecosystem map

This is a map of responsibilities, not a mandate that every deployment run every
project.

| Layer | Owner | Responsibility | Explicitly does not own |
|---|---|---|---|
| Machine and network operations | Mycelium | Identity, access, topology, discovery, resource observations, signed distribution, fleet health | Application message routing or inference |
| Bootstrapping | Genesis | Network boot, image assembly, disk provisioning, Tang/Clevis enrollment, first Mycelium identity | Ongoing fleet management |
| Transport | Unibus | Authorized message and event transport between independently useful endpoints | Fleet inventory or service lifecycle |
| Composition | Canvas | Human and agent-facing composition of applications, media, and tools | Transport and machine provisioning |
| Inference | Bifrost | Inference interfaces and routing | General service supervision |
| Compute execution | Yggdrasil and UMIE | Heterogeneous accelerator discovery and execution | Host identity or topology authority |
| Workload substrate | Shroud | Workload packaging and execution drivers | Bare-metal ownership |
| Storage substrate | IPFS and compatible providers | Content-addressed distribution and pull-through caching | Identity policy |
| Product-specific engines | For example, PedalKernel | Domain implementation and product behavior | Shared infrastructure contracts |

## Shared contracts

Shared contracts should be small, versioned, provider-neutral, and owned once.
Likely contracts include:

- Peer identity and signed claims.
- Resource observations for compute, storage, capture, and attached hardware.
- Service advertisements with freshness and provenance.
- Artifact manifests, digests, signatures, and deployment policy.
- Topology observations and reachability measurements.
- Security findings and remediation evidence.

A shared contract is not permission to share internal databases or Rust types
between projects. Each consumer should accept the contract through a narrow
adapter, and static/local providers should be usable in tests to prove that no
consumer depends on Mycelium.

## Deployment profiles

The same contracts should support several deliberately different profiles:

- **Embedded:** ESP32-class devices participate through constrained Unibus and
  identity interfaces without pretending to be full Linux hosts.
- **Edge:** Raspberry Pi and small Linux nodes provide local discovery, routing,
  caching, and boot services.
- **Workstation:** macOS, Linux, and Windows machines expose resources while
  retaining native user and security models.
- **Compute:** GPU nodes run UMIE/Yggdrasil and receive signed artifacts according
  to policy.
- **Site:** one or more replaceable nodes provide resilient local services and
  connect sites without requiring a permanent central controller.

## What “OS” means here

fungOS should initially mean an interoperable operating environment, not a Linux
distribution. The substrate must work with existing Debian, Raspberry Pi OS,
macOS, Windows, and embedded deployments before an opinionated image earns its
place.

A later FPL Linux image can package the same components and contracts. It should
be a replaceable distribution profile built by Genesis, not the definition of
the ecosystem.
