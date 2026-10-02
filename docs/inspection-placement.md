# Network inspection placement

Mycelium models inspection independently of Suricata, Zeek, eBPF, or a
firewall vendor. The planner consumes two kinds of facts:

- coverage intent: logical networks, inspection depth, and redundancy;
- candidate observations: evidenced visibility, current capacity, trust,
  observation method, and failure domain.

It deterministically selects broad coverage first, then capacity and
reliability. Redundant placements in the same failure domain do not count as
independent coverage. Missing or uncertain visibility is reported as a blind
spot.

Candidate observations can currently be supplied as JSON while topology-based
candidate derivation matures:

```json
[
  {
    "node_id": "signed-peer-id",
    "hostname": "pris",
    "site": "wagar-house",
    "method": "gateway",
    "depths": ["host_flows", "packet_metadata"],
    "visible_networks": ["cctv", "lab"],
    "logical_cpus": 8,
    "memory_available_bytes": 4294967296,
    "load_per_cpu": 0.2,
    "uptime_seconds": 86400,
    "trusted": true,
    "stable_power": true,
    "failure_domain": "pris-ups"
  }
]
```

Plan without changing any device:

```sh
mycelium security inspection plan \
  --network cctv --network lab \
  --depth packet-metadata \
  --redundancy 1 \
  --candidates candidates.json
```

Use `--json` to retain assessments, scores, reasons, and blind spots for IaC.
Candidate files are an interchange/runbook format, not a second inventory.
The next derivation layer should create these facts from signed peer health,
physical links, network bindings, gateway routes, mirror configuration, and
power-domain observations.

Inspection depths are intentionally engine-neutral:

- `host_flows`: per-host connection/listener/firewall metadata;
- `packet_metadata`: packet/flow headers and protocol metadata;
- `deep_packets`: payload/signature inspection.

An engine or deployment driver must explicitly advertise a supported depth.
The planner never treats software installation as proof of traffic visibility.
