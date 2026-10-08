# Explicit Debian software updates

Mycelium coordinates admission and health/recovery; APT authenticates repository
metadata/downloads and dpkg owns package files and conffiles. The native binary
activation path remains separate. Never assign both installers to one executable.

This first slice is local Linux root, manual, and one already-installed package
at a time. It does not enroll a node, install initial dependencies, gossip APT
policy, automatically choose versions, or deploy an origin. Linked-set rollback,
application data migrations and packages with maintainer scripts/triggers are
not qualified and are rejected. Package payloads retain their own licenses.

## Authority and preparation

Use a root-owned Mycelium home, not a user's writable enrollment directory.
Repository-specific `Signed-By`, expiry checks and independently admitted public
keys remain prerequisites. Refresh sources using `apt-get update --error-on=any`.
The serving tier must not hold the signing private key; no credentials belong in
repository URLs or plans.

`software-services.json` must be a root-owned mode-0600 regular file. Bind the
Debian package name to an existing explicit unit and bounded readiness probe:

```json
{
  "unibus-core": {
    "unit": "unibus-router.service",
    "timeout_secs": 15,
    "readiness": {
      "kind": "unix",
      "path": "/run/unibus/health.sock",
      "request": "health\n",
      "expect_prefix": "READY unibus\n"
    }
  }
}
```

The Unibus owner supplies the authenticated health endpoint and credentials;
Mycelium does not create grants. Canvas can use the existing `unix_json` probe
against its owner-local control socket. Socket ownership, executing binary digest
and stable application replies are checked by the shared native-service adapter.
The existing unit must execute the selected `/usr/bin` binary directly.

## Plan, apply, recover

```sh
sudo env MYCELIUM_HOME=/var/lib/mycelium mycelium software apt plan \
  unibus-core EXACT_VERSION /usr/bin/unibus-router > apt-plan.json
# Read the digest printed in that plan; authorize that exact digest:
sudo env MYCELIUM_HOME=/var/lib/mycelium mycelium software apt apply \
  apt-plan.json EXACT_PLAN_DIGEST --write
# After interruption or failed recovery:
sudo env MYCELIUM_HOME=/var/lib/mycelium mycelium software apt recover --write
```

Plan is read-only: installed version, exact archive hashes, architecture, binary
ownership, solver scope and the local health binding contribute to its digest.
Apply refreshes signed metadata, rejects a stale plan, stages both exact versions
through APT, verifies archive identities/hashes and rejects scripts/triggers.
Held packages and dependency-expanded/removal transactions are refused. A
root-private lock serializes these operations; unrelated package managers remain
an operator coordination concern. dpkg applies only the staged package, without
running other-package triggers, and preserves operator conffiles.

Before stopping the service, a synced `apt/activation-pending.json` records the
previous archive and executable digest. A healthy candidate clears it. A failed
candidate returns failure even when restoration succeeds. Failed restoration
retains the checkpoint. Explicit recovery re-admits the local binding, restores
the retained archive and verifies health; no silent success or shell commands
from publishers. Failed staging uses a fresh attempt directory on retry.

The checkpoint is not automatically recovered at daemon startup yet. Keep
retained attempts while recovery is pending. Neither archive rollback nor this
checkpoint reverses application data/schema migrations.

## Qualification ownership

`fungos/packages/src/bin/edge-apt-*` owns disposable disk assembly and assertions.
Canvas packages come from Dock's `tools/canvas-deb`; Unibus retains its existing
owner packager. Test fixtures reuse owner binaries for baseline/upgrade and an
explicit exit-1 binary for failure. They are not distinct production releases.
No cloud apply, live peer update or replacement of the streamed VM is needed.
