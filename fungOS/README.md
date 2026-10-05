# fungOS

`fungOS` is the working strategy map for the open FPL computing ecosystem: a
mesh-oriented substrate that helps people discover, trust, provision, operate,
and safely automate heterogeneous devices.

The name is provisional. It is memorable and fits Mycelium, but naming should
not dictate architecture or delay useful work.

This directory is intentionally not an implementation repository or a second
source of truth for component behavior. Each project owns its contracts and
documentation. These documents explain how the projects fit together, what FPL
should standardize, and how an open ecosystem around them can grow.

## Thesis

Software implementation is becoming cheaper. Durable value increasingly comes
from trusted interfaces, interoperability, distribution, operational knowledge,
and a community aligned around a shared substrate.

FPL should therefore make the foundational primitives easy to adopt, embed,
replace, and extend. It can build sustainable products and services through
stewardship, integration, certification, support, hosted operation, and selected
product-level commercial licensing.

## Documents

- [Ecosystem map](ecosystem.md) — project ownership, boundaries, and shared contracts.
- [Repository inventory](repository-inventory.md) — current GitHub ownership, visibility, and licenses.
- [Community and GTM](community-and-gtm.md) — who this is for and how adoption compounds.
- [Licensing](licensing.md) — a default licensing decision framework.

## Guardrails

- Open protocols and portable data before a vertically integrated suite.
- Each capability has one owning project; neighboring projects call it.
- Discovery reports availability, never authority.
- Deterministic operations with narrow, optional agent assistance.
- Local-first and self-hostable operation; hosted services are conveniences.
- Unix principals and standard operating-system controls remain first-class.
- A component must remain useful without the rest of the FPL ecosystem.
- Strategy documents describe direction; executable contracts remain authoritative.

## Near-term outcome

Prove one coherent journey on real mixed hardware:

1. Boot or install a node.
2. Establish its machine identity and enroll it safely.
3. Discover its topology, services, and resources.
4. Grant a person or workload least-privilege access.
5. Deliver signed software according to declared policy.
6. Observe health and security posture.
7. Remove or replace any individual control-plane component without rebuilding
   the fleet.

That journey is more useful than claiming to have built an all-encompassing OS.
