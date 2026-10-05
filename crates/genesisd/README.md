# genesisd

`genesisd` is the standalone, deterministic manifest and artifact service for
Genesis machine birth. It owns durable boot profiles, machine intents, birth
receipts, and digest-pinned artifact bytes. DHCP, PXE policy, Mycelium
enrollment, and vendor-specific provisioning remain adapters outside this
crate.

## Run

```console
cargo run -p genesisd --bin genesisd -- \
  --root ./genesis-state \
  --listen 127.0.0.1:8088
```

The read-only HTTP projection serves health, profiles, intents, receipts, and
artifacts:

```text
GET /health
GET /v1/profiles/{sha256}
GET /v1/intents/{sha256}
GET /v1/receipts/{machine}
GET /v1/artifacts/{sha256}
GET /v1/boot/{name}.ipxe
```

Mutations are local-only through `genesisctl` in this first slice:

```console
genesisctl --root ./genesis-state profile put profile.json
genesisctl --root ./genesis-state intent put intent.json
genesisctl --root ./genesis-state plan intent.json profile.json
genesisctl --root ./genesis-state artifact put "$SHA256" ./artifact
genesisctl --root ./genesis-state boot put bootstrap.ipxe ./bootstrap.ipxe
genesisctl --root ./genesis-state receipt put receipt.json
```

The `plan` command is pure and deterministic. It validates that an intent
references the supplied profile and emits the exact artifact URLs and digests
an operator or future DHCP adapter must materialize.

## Recovery runbook

1. Stop `genesisd`; the state directory is self-contained and requires no
   separate database.
2. Back up or move the state directory as one filesystem tree.
3. Verify artifact filenames against their contents with `sha256sum`.
4. Inspect profiles, intents, and receipts as JSON. Profiles and intents are
   immutable by digest; receipt transitions can only advance.
5. Start `genesisd` with the recovered state directory and query `/health`.
6. Fetch each planned artifact through `/v1/artifacts/{sha256}` and verify its
   digest before restoring any boot-service adapter.

Conflicting immutable content, invalid receipt transitions, and digest
mismatches fail loudly. The HTTP service cannot mutate birth state.
