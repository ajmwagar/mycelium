# Compute boot and update verification

The GPU stays with its recorded owner except during an explicitly authorized,
timed handoff. Follow [GPU-HANDOFF.md](GPU-HANDOFF.md) and re-inventory every
current GPU user. A newly started workload is not covered by an old drain list.

## Provisioned guest startup

Install `fungos-nvidia-ready.service` and `umie.service` in
`/etc/systemd/system`, then run `systemd-analyze verify` and
`systemctl daemon-reload`. Keep UMIE disabled while staging. Provision compatible
kernel modules, firmware, runtime libraries and the model separately as described
in the handoff runbook. No driver or model is silently downloaded by these units.

With the GPU assigned, enable UMIE and cold-boot the guest. Its required readiness
unit runs `depmod`, `modprobe nvidia`, `modprobe nvidia_uvm`, then `nvidia-smi -L`,
with a 60-second deadline. Do not manually load modules during this test: that
would hide a boot-order failure. Verify device ownership, GPU-backed UMIE memory,
and a correct `/v1/systemone` response, in addition to native unit state.

Without a GPU the readiness unit must fail visibly; it must not stop independent
Canvas, Unibus or Mycelium units. This negative case was verified on 2026-10-05.

## Locally authorized activation

Merge the `umie` entry from `software-services.json` into the guest's existing
`/var/lib/mycelium/software-services.json`, retaining its Canvas/Unibus entries
and owner-only permissions. Use a CLI/daemon with `http_json` readiness support.
The local operator owns the unit, loopback endpoint, request and expected answer;
the signed package cannot change those permissions.

The fixture posts a Laya decision request (no physical lighting operation) and
requires `/answers/lighting/choice` to equal `on`. It has a five-second request
deadline and a 256 KiB response bound. Redirects, proxies, remote endpoints,
non-success status, malformed JSON and wrong answers are rejected. A listening
socket must also belong to the supervised process; an unrelated listener cannot
claim readiness. `/health` alone is not the activation predicate.

Keep the compute policy manual during the experiment. Publish a new compatible
UMIE build on `fungos-compute-test` through the existing release authority. Verify
the signature, target and content digest in the guest catalog before activation:

```sh
export MYCELIUM_HOME=/var/lib/mycelium MYCELIUM_NO_AUTOSTART=1
mycelium software activate umie --channel fungos-compute-test --dry-run --json
mycelium software activate umie --channel fungos-compute-test --write --json
```

Require native service verification, a real response and GPU allocation before
calling the update successful. To exercise recovery, publish an explicitly
identified incompatible application candidate only on this isolated manual
channel. Require activation to report failure, restore the previous `current`
link, restart the old service and pass its real inference predicate. Check the
restored executable digest separately. Do not interpret a staged download or
successful symlink switch as application recovery.

Restore a healthy catalog head after the intentional failure; never enable
automatic updates against an intentionally bad latest candidate. Return the GPU
and restore every previously running host workload before cancelling recovery.

## Evidence boundary

The original temporary handoff proved inference, not unattended cold boot or
real GPU update rollback. The native readiness units and bounded HTTP predicate
have passed unit/configuration tests; those live GPU acceptance tests remain
separate. Existing updater rollback tests exercise failed service recovery with
recorded lifecycle fixtures, not a substitute for this hardware experiment.
