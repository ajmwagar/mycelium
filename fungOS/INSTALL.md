# Install and first boot

Start with an isolated QEMU guest. The edge runtime, claim enrollment, native
Wayland services and signed updates have been qualified there. A rootfs tarball
is **not** an installer ISO or a bootable physical-machine disk.

## Choose a path

| Target | Starting point |
| --- | --- |
| Existing Linux/macOS machine | Install Mycelium using the repository README; this does not install fungOS. |
| Linux KVM development host | Build a runtime profile, then follow the QEMU runbook. |
| Raspberry Pi | Use the board-specific Pi instructions; an arm64 runtime alone lacks board boot support. |
| Bare-metal PXE | Genesis boot coordination plus an explicitly trusted enrollment delivery path; ordinary PXE does not authorize enrollment. |

See [profiles](profiles.md), [QEMU setup](qemu/RUNBOOK.md),
[Pi support](pi/README.md) and [physical first-contact boundaries](../docs/genesis-first-contact.md).
There is no public installer download qualified by this runbook.

## QEMU journey

Use a Linux KVM host. Build on that host, not the target Pi. Keep private
provisioning and runtime state outside the checkout.

1. Build and inspect the chosen [runtime profile](base/RUNBOOK.md).
   `edge` includes Canvas runtime dependencies; `headless-edge` does not.
   First-party application binaries are supplied separately as signed packages.
2. Assemble the tracked QEMU overlay with the authorized static Mycelium
   bootstrap, matching kernel/DRM module and public recovery SSH key. Use the
   [persistent-root builder](qemu/RUNBOOK.md#persistent-root-experiment) with a
   new output path. Never use an attached physical disk or another peer's root.
3. On the authority, create a short-lived peer invitation with the expected
   name, site and reachable certified seeds. Build its
   [owner-only claim envelope](qemu/README.md#one-use-claim-disk), attach it
   read-only and boot. Keep the authority's private keys off the guest.
4. Verify enrollment separately from boot. Then detach/delete the consumed
   claim media and plaintext log; retain the persistent guest root disk.
5. Install [local service bindings and package policy](edge/README.md#manual-runbook).
   Select the stable `node.PEER_ID`, not a mutable hostname. Configure Unibus
   through its own interfaces, with new credentials rather than another
   machine's token files. Allow peer downloading to finish, then explicitly
   activate first installations. Automatic policy does not install an absent app.
6. Verify the native services, configure update policy, and reboot. The first
   signed Mycelium bootstrap activation is explicit; subsequent updates use
   the automatic runner's age, rollout and retry gates.

The QEMU fixture is a root-owned development session, not the production
least-privilege seat configuration. Canvas Linux owns Wayland/KMS; do not add
Xorg or another compositor to make a failed display check pass. Compositor
automatic activation remains gated on output/renderer health.

## Acceptance checks

Inside the enrolled guest, using its existing managed CLI:

```sh
mycelium node status --json
mycelium software reconcile --dry-run --json
mycelium update policy status --json
systemctl is-active mycelium mycelium-update.timer
# Display edge only:
systemctl is-active unibus-router canvas-compositor canvas canvas-edge
```

Record and compare hashes of `peer.key`, `pki/node.pem`, `/etc/machine-id` and
the SSH host public key across a reboot without the claim disk. Healthy units
are not proof of a displayed desktop: check an actual framebuffer/receiver and
application readiness separately. See [qualification evidence](packages/update-safety.md).

## Troubleshooting

- **Cannot reach the daemon:** inspect `systemctl status mycelium` and
  `journalctl -u mycelium`. Enrolled fungOS CLI calls do not implicitly spawn
  a daemon while its supervisor is restarting. Recover through systemd.
- **Manifest present, artifact absent:** confirm matching placement, trusted
  signer, compatible target and a reachable peer holding verified bytes.
  Discovery of a peer is not proof that it serves the package protocol.
- **TLS name mismatch:** use a peer certificate valid for the configured
  address. An SSH forward does not change the certificate's valid names.
  Do not bypass verification.
- **Missing cursor:** rebuild the tracked edge runtime. Display image assembly
  rejects an archive missing its configured cursor before writing boot artifacts.
- **Waiting update:** inspect policy and staging status; preserve the age and
  rollout gates. Do not repeatedly republish an immutable version.
- **Application activation fails:** inspect its journal and activation record.
  Native activation verifies health and restores the previous release on failure.
  Do not let APT and native activation both own the same component.

## Recovery

Retain a public-key SSH recovery route and the previous disk/artifact before
testing updates. Restart only the named qualification guest or service. Do not
re-enroll a healthy existing identity to fix networking or service drift, and
do not include a live peer's keys or reusable claims in distributed images.
