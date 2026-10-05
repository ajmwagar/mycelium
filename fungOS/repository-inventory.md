# Repository ownership and licensing inventory

Snapshot date: 2026-10-04.

This inventory records the repositories currently relevant to the fungOS/FPL
systems map. It is intentionally narrower than every repository owned by Avery
Wagar or Future Present Labs. Visibility comes from authenticated GitHub
metadata. License declarations are checked against both GitHub's detector and
the locally available repository manifests; a blank GitHub result is not proof
that a private repository is unlicensed.

## Open upstream projects

| Capability | Repository | Visibility | Declared license | Notes |
|---|---|---|---|---|
| Fleet identity, access, topology, discovery, and distribution | [`ajmwagar/mycelium`](https://github.com/ajmwagar/mycelium) | Public | MIT OR Apache-2.0 | GitHub identifies the MIT file; the Rust workspace and paired license files declare the dual license. |
| Clock-aware network audio | [`ajmwagar/isochrone`](https://github.com/ajmwagar/isochrone) | Public | MIT OR Apache-2.0 | GitHub identifies Apache-2.0; the workspace includes both license files. |
| SDR orchestration and DSP contracts | [`ajmwagar/radioman`](https://github.com/ajmwagar/radioman) | Public | MIT OR Apache-2.0 | Appropriate reusable edge capability. |
| Circuit and pedal DSP product engine | [`ajmwagar/pedalkernel`](https://github.com/ajmwagar/pedalkernel) | Public | AGPL-3.0-or-later with additional terms | GitHub reports `Other`; the workspace manifests declare AGPL and the root license contains the additional condition. Treat commercial embedding separately. |
| Work tracking for coding-agent fleets | [`FuturePresentLabs/marbles`](https://github.com/FuturePresentLabs/marbles) | Public | MIT | Supporting development infrastructure, not a fungOS runtime dependency. |
| Decision Catalog Protocol | [`FuturePresentLabs/dcp`](https://github.com/FuturePresentLabs/dcp) | Public | MIT OR Apache-2.0 locally | GitHub does not currently detect a license. Add canonical root license files before presenting it as clearly licensed FOSS. |
| Agent skills | [`FuturePresentLabs/agent-skills`](https://github.com/FuturePresentLabs/agent-skills) | Public | Per-skill/undetected | Supporting extension catalog. The repository needs an explicit top-level licensing policy for shared material. |

## Current private implementation projects

| Capability | Repository | Visibility | Declared license | Boundary observation |
|---|---|---|---|---|
| Message and event transport | [`FuturePresentLabs/unibus`](https://github.com/FuturePresentLabs/unibus) | Private | Proprietary | Current workspace declares `LicenseRef-Proprietary`. If Unibus is intended as an open fungOS primitive, licensing and publication are unresolved work. |
| Inference gateway | [`FuturePresentLabs/bifrost`](https://github.com/FuturePresentLabs/bifrost) | Private | Not declared at repository root | Its vendored FPL SDK declares BUSL-1.1, which does not establish Bifrost's license. |
| Heterogeneous inference engine | [`FuturePresentLabs/umie`](https://github.com/FuturePresentLabs/umie) | Private | Apache-2.0 | License already matches the reusable-substrate strategy; visibility is the remaining publication decision. |
| Compute scheduling and routing | [`FuturePresentLabs/yggdrasil`](https://github.com/FuturePresentLabs/yggdrasil) | Private | MIT | License already matches the reusable-substrate strategy; visibility is the remaining publication decision. |
| MicroVM workload runtime | [`FuturePresentLabs/shroud`](https://github.com/FuturePresentLabs/shroud) | Private | GPL-3.0-or-later repository default; MIT deploy client | The root license is GPL-3.0-or-later, `shroud-deploy` and `shroud-vpc` declare it explicitly, and `shroud-deploy-client` has its own MIT license. Other workspace crates omit package-level declarations and should be treated as covered by the root license unless clarified. |
| Older/alternate Shroud repository | [`ajmwagar/shroud`](https://github.com/ajmwagar/shroud) | Private | Other/mixed | Duplicate name and overlapping description; establish the canonical upstream before fungOS references Shroud. |
| Canvas compositor and Dock product | [`FuturePresentLabs/dock`](https://github.com/FuturePresentLabs/dock) | Private | Proprietary | Canvas currently exists as crates inside Dock and inherits its proprietary workspace license. Extract public Canvas contracts or crates before calling Canvas an open primitive. |
| Voice/assistant application | [`FuturePresentLabs/JARVIS`](https://github.com/FuturePresentLabs/JARVIS) | Private | Mixed/unclear | `jarvis-dsp` declares MIT OR Apache-2.0; no repository-wide declaration was found. Product application, not required substrate. |
| OIDC and organization identity | [`FuturePresentLabs/fpl-auth`](https://github.com/FuturePresentLabs/fpl-auth) | Private | Not declared | Optional identity provider. Mycelium and fungOS must remain provider-neutral and locally survivable. |
| Storage control plane | [`FuturePresentLabs/fpl-storage`](https://github.com/FuturePresentLabs/fpl-storage) | Private | MIT | GitHub and local manifest agree. Publication is a product decision. |
| Build and delivery pipeline | [`FuturePresentLabs/fab`](https://github.com/FuturePresentLabs/fab) | Private | MIT | Produces artifacts; fungOS consumes signed outputs rather than embedding Fab. |
| Cloud and site deployment state | [`FuturePresentLabs/shared-infra`](https://github.com/FuturePresentLabs/shared-infra) | Private | Mixed/undeclared at root | Correctly private because it contains operational infrastructure. Individual reusable components need their own licenses. |
| Infrastructure as code | [`FuturePresentLabs/fpl-opentofu`](https://github.com/FuturePresentLabs/fpl-opentofu) | Private | Not declared | Deployment configuration rather than a fungOS runtime primitive. |
| Firmware research and implementations | [`FuturePresentLabs/reversal`](https://github.com/FuturePresentLabs/reversal) | Private | Component-specific MIT or MIT OR Apache-2.0 | No single root license was found. Publish reusable HAL/ABI crates deliberately rather than opening research artifacts accidentally. |
| Audio/media system | [`FuturePresentLabs/synesthesia`](https://github.com/FuturePresentLabs/synesthesia) | Private | MIT | Consumer/provider of shared resource and service contracts, not required by fungOS. |
| MCP infrastructure | [`FuturePresentLabs/fpl-mcp`](https://github.com/FuturePresentLabs/fpl-mcp) | Private | Not declared | Optional service/protocol integration. |

## Planned repositories and contracts

These names do not currently exist in either mapped GitHub namespace.

| Proposed repository | Initial owner | Visibility | Proposed license | Purpose |
|---|---|---|---|---|
| `ajmwagar/fungos` | Avery Wagar | Public | MIT OR Apache-2.0 | Reference profiles, image recipes, release manifests, architecture, and community documentation. |
| `ajmwagar/genesis` | Avery Wagar | Public | MIT OR Apache-2.0 | Standalone provisioning service and boot-provider adapters. |
| `ajmwagar/fpl-boot-contract` | Avery Wagar | Public | MIT OR Apache-2.0 | Provider-neutral boot intent, profile, receipt, and wire schema. |

The repositories should be created only when each has a buildable first commit,
license files, security policy, ownership metadata, and a concise boundary. Empty
branding repositories create more confusion than discoverability.

## Immediate findings

1. **Do not mass-transfer existing repositories.** The personal namespace is the
   established public upstream today; FPL already owns much of the private product
   and operational layer.
2. **Unibus is not currently open.** Its architectural role may be foundational,
   but its actual workspace license is proprietary. Decide deliberately rather
   than describing it as FOSS prematurely.
3. **Canvas is not an independent repository.** It currently inherits Dock's
   proprietary license. Public contracts can be extracted without forcing the
   entire product open.
4. **Resolve the two Shroud repositories.** Pick one canonical implementation and
   document whether a GPL repository with a separately MIT-licensed deployment
   client remains the intended split. Add explicit license metadata to every crate.
5. **Add missing root license files.** DCP is public and locally declares a dual
   license but GitHub cannot detect it. `agent-skills` needs an explicit repository
   policy. Private repositories marked "not declared" need a decision before any
   publication.
6. **Keep deployment state private.** `shared-infra`, credentials, site inventory,
   customer state, and signing material must never move into a public fungOS repo.

## Maintenance

Visibility and license status change over time. Refresh this document from GitHub
metadata before a launch or repository transfer, and verify the actual `LICENSE`
files and package manifests rather than relying only on GitHub's detector.
