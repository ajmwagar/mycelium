---
name: mycelium-network-operator
description: Inspect, model, plan, and safely operate networks managed by the Mycelium CLI. Use for topology discovery, logical networks, allocation receipts, physical port bindings, VLANs, DHCP, DNS, WireGuard, jump-host routing, UniFi, NETGEAR, EdgeOS, and network drift or remediation tasks.
---

# Mycelium network operations

Use Mycelium's shared topology and capability contracts. Do not bypass a driver with vendor commands unless diagnosing the driver itself.

## Workflow

1. Run `mycelium daemon status`, `mycelium peers`, and `mycelium topology`.
2. Refresh evidence with `mycelium scan` when observations may be stale.
3. Inspect `mycelium allocations list`, `mycelium networks list`, and `mycelium networks drift`.
4. Derive or import allocations before adopting logical intent. Keep allocation state separate from credentials.
5. Use `mycelium networks bindings` to inspect physical placement.
6. Generate plans with `mycelium networks plan --json`. Treat blockers as missing facts, not prompts to guess.
7. Review mutations with `--dry-run`; require explicit `--write` for application.
8. Rescan and verify drift after every mutation.

Prefer `mycelium ssh`, `exec`, `scp`, and `tunnel` over manually reconstructing jump-host routes. Preserve secrets in environment variables and never place credentials in topology, plans, logs, or skill output.

When a capability is absent, report the missing driver contract. Do not claim a VLAN, DHCP pool, route, or WLAN change succeeded without its declared read-only postcondition.
