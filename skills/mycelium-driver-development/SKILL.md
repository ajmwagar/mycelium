---
name: mycelium-driver-development
description: Build, extend, and test Mycelium hardware or service drivers. Use when adding support for routers, switches, access points, BMCs, operating systems, DHCP/DNS services, firmware, or new implementations of shared Mycelium capabilities.
---

# Mycelium driver development

Implement shared concepts through narrow capabilities. Extend the common representation before introducing a vendor-only command surface.

## Contract

1. Reuse capability IDs from `mycelium-core`; add a shared ID only when the concept is vendor-neutral.
2. Declare parameter and return shapes through `CapSpec`.
3. Keep observation read-only and attach provenance to every topology fact.
4. Route mutation through `Device::invoke`, `ExecContext`, and the write/dry-run gate.
5. Return structured `Value` output. Do not make callers parse display text.
6. Pair every planned action with a read-only verification capability and predicate.
7. Fail loudly for unsupported behavior or incomplete evidence.

Use pure parsers and recording transports for tests. Run `cargo check` while iterating, targeted tests when complete, and build binaries only when an artifact is needed. Preserve credential references rather than secret values in durable inventory.

Keep vendor translation inside its driver. Network intent, action plans, allocation receipts, and topology types belong to shared crates and must remain usable by other drivers.
