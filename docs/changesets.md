# Intent, proposals, and executable changes

Mycelium uses three boundaries. They are intentionally not interchangeable.

1. **Intent** states the desired outcome without vendor commands.
2. **Proposal** is read-only analysis: placement, reachability, migration diff,
   or another recommendation that cannot mutate infrastructure.
3. **ActionPlan** is the only executable cross-driver change format.

An engine-specific proposal must be lowered through the capabilities currently
advertised by managed devices before it becomes an `ActionPlan`. Drivers never
execute proposal formats directly.

## Execution

`ActionPlan` execution has one typed mode:

- `plan`: validate the complete plan and invoke driver dry-runs;
- `apply`: preflight the complete plan, execute actions in order, and verify
  each postcondition through a read-only capability.

The older RPC request containing separate `write` and `dry_run` booleans is
accepted during the pre-1.0 migration, immediately normalized, and rejects both
flags together. New clients use the typed request.

Every plan has a canonical SHA-256 digest, and every ordered action has a stable
ID derived from that digest. The daemon writes an execution receipt before the
first action and after every state transition under:

```text
$MYCELIUM_HOME/executions/<plan-digest>-<started-at>.json
```

Receipts distinguish `planned`, `running`, `succeeded`, and `failed`, retain
per-action outputs and verification evidence, and identify partial failure.
They do not claim rollback. Compensation must be modeled as another explicit,
reviewable action.

Mycelium-owned intent uses the parallel `StateChangePlan` transaction boundary.
It shares canonical identity, typed execution mode, durable receipts, and
fail-loud persistence, but it does not invent a device capability or
postcondition. Network adoption, physical bindings, DHCP intent, discovery
scopes, and allocation records use this boundary. If persistence fails, the
daemon restores its previous in-memory state before recording failure.

Inspect both device and state receipts with:

```sh
mycelium executions
mycelium executions --json
```

## Planner rule

A type ending in `Proposal` is advisory. A type ending in `Plan` must either be
an `ActionPlan` or must never cross an apply boundary. New executable plan
formats are not permitted; extend the shared capability/action vocabulary
instead.
