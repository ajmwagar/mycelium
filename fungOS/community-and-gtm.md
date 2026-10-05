# Community and go-to-market

## Initial community

Start with people who already feel the pain of operating heterogeneous hardware:

- Home-lab and small-studio operators.
- Creative technologists with audio, video, MIDI, cameras, and GPUs.
- Small AI teams assembling mixed consumer and workstation compute.
- Makers moving between Raspberry Pi, embedded devices, Macs, and Linux servers.
- Organizations that need understandable security posture without a heavyweight
  enterprise control plane.

The first promise should be concrete:

> See what you own, reach it safely, and keep it healthy without surrendering it
> to a proprietary cloud.

## Adoption wedge

Lead with one independently useful tool: Mycelium inventory, topology, and secure
access across a real mixed fleet. Then let users opt into signed distribution,
bootstrapping, transport, compute, and composition as their needs grow.

Avoid marketing “an agent operating system” before the underlying runbook is
reliable. Demonstrate outcomes:

- Find an unknown device or service.
- Access a machine without distributing permanent private keys.
- Restore a failed node from a reproducible image.
- Place a workload on an appropriate GPU.
- Update a fleet artifact safely and verify the result.
- Continue local operation while an external identity provider is unavailable.

## Community flywheel

1. Publish boring, stable contracts and a small working CLI.
2. Maintain excellent install, first-run, and recovery documentation.
3. Ship reproducible examples from the actual FPL fleet, with secrets removed.
4. Accept drivers, recognizers, policy packs, and hardware profiles through
   bounded extension interfaces.
5. Test community contributions against simulators and inexpensive reference
   hardware.
6. Publish compatibility results and recognize maintainers.
7. Feed proven integrations back into the shared catalog.

The valuable network effect is a trusted compatibility corpus: hardware quirks,
service recognizers, secure defaults, and reproducible operating knowledge.

## Sustainable offerings

Open adoption should remain useful without payment. Revenue can come from:

- Supported hardware and certified reference systems.
- Fleet migration, integration, and security-hardening services.
- Hosted rendezvous, observability, artifact distribution, and identity bridges.
- Long-term support releases and compliance evidence packs.
- Commercial licensing for selected product engines where closed embedding is a
  direct substitute for contributing upstream.

Hosted offerings must use public interfaces and exportable state so they improve
the open ecosystem instead of becoming a dependency trap.

## Near-term GTM experiments

Each experiment should have one observable success measure:

| Experiment | Evidence |
|---|---|
| Five-minute Mycelium install and inventory | A new user reaches a useful topology without assistance |
| Mixed-fleet reference deployment | Pi, macOS, Linux, and GPU hosts remain healthy for 30 days |
| Driver/recognizer contribution guide | An external contributor ships one integration |
| Public compatibility catalog | Users can select known-working hardware before purchase |
| Recovery demonstration | A blank node reaches an enrolled, patched state from a documented runbook |
| Security posture report | Findings are actionable without requiring a hosted account |

## Things not to optimize yet

- A universal desktop environment.
- Replacing every existing Linux distribution.
- A proprietary marketplace before extension contracts stabilize.
- Autonomous agents with broad ambient authority.
- Bundling every FPL repository into one release train.
- Branding work that outruns a repeatable install and recovery experience.
