# Licensing framework

Licensing follows the economic role of a component, not a single ecosystem-wide
ideology.

## Defaults

Use `MIT OR Apache-2.0` for foundational components whose value grows through
ubiquitous adoption and embedding:

- Protocols, schemas, and wire formats.
- SDKs, clients, and interoperability libraries.
- Drivers, recognizers, and provider-neutral adapters.
- Boot and resource-observation contracts.
- Core infrastructure primitives intended to become compatibility targets.

Apache-2.0 contributes an explicit patent grant; the dual-license convention is
familiar and low-friction in the Rust ecosystem.

Consider `AGPL-3.0` with a contributor agreement and a separately negotiated
commercial license when the complete implementation is itself the product and a
closed derivative would directly substitute for upstream participation:

- Product-level engines such as PedalKernel.
- A complete hosted control plane.
- Finished applications whose operation, rather than interoperability, is the
  primary value.

## Decision test

Ask these questions in order:

1. Does adoption become more valuable when this code is embedded everywhere?
   Prefer MIT/Apache-2.0.
2. Is the stable public interface more strategically important than this
   implementation? Prefer MIT/Apache-2.0.
3. Can a closed fork sell essentially the same complete product while avoiding
   upstream participation? Consider AGPL plus commercial licensing.
4. Is the concern specifically a hosted modification never distributed to
   users? AGPL's network-use provision may be material.
5. Is a custom additional license condition needed? Get qualified legal review
   before describing the result as standard AGPL or OSI-approved open source.

## Contributor agreements

A CLA can preserve the ability to offer commercial terms and defend the project,
but it creates a trust burden. If used:

- State exactly what rights contributors grant and retain.
- Keep the public project governance and relicensing policy visible.
- Avoid implying that a CLA is required for every permissively licensed utility.
- Prefer a lightweight developer certificate of origin when commercial
  relicensing is not an actual requirement.

## Working ecosystem split

- Shared FPL primitives and contracts: MIT OR Apache-2.0.
- Replaceable adapters and community integrations: MIT OR Apache-2.0.
- Product engines with direct closed-embedding risk: AGPL plus commercial terms.
- Hosted convenience services: choose based on whether the implementation or the
  public contract is the strategic asset.

Licenses should be declared by their owning repositories. This document records
the decision framework; it is not a substitute for each project's `LICENSE`,
`README`, or qualified legal advice.
