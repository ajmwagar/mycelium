# First isolated fungOS boot

This harness turns the reproducible `fungOS/base` root filesystem into a
kernel-specific initramfs for the first Genesis QEMU boot. It is deliberately
separate from the portable base image: the host kernel is a boot-profile input,
not part of fungOS base.

The experiment uses an isolated Linux bridge with no physical uplink. A small
lease-only dnsmasq instance represents an existing router; the reviewed Genesis
dnsmasq configuration provides ProxyDHCP and the one-file TFTP service. Genesis
serves the iPXE scripts, kernel, and initramfs over HTTP.

`rootfs-overlay/init` is PID 1 only long enough to mount the kernel filesystems
and exec the base image's systemd. The proof service emits
`FUNGOS_QEMU_NETWORK_OK address=...` and `FUNGOS_QEMU_BOOT_OK` only after
`network-online.target` and a global address. A boot without userspace network
convergence fails loudly.
The initramfs builder adds the host's statically linked BusyBox only as the
early `/init` interpreter; it is not installed into the fungOS base image.

All runtime state belongs under a caller-selected scratch directory. The
cleanup runbook removes only the named bridge, TAP, dnsmasq processes, and
scratch directory created for the experiment.

The checked-in `lease-dnsmasq.conf` is intentionally lease-only and may be
used only on the isolated `genesis0` bridge. The Genesis-rendered second
configuration remains ProxyDHCP-only and machine-scoped.

## One-use claim disk

Capture `mycelium pair --kind peer` output into an owner-only file (`umask 077`),
then build the disk without copying its claim through the terminal:

```sh
sh fungOS/qemu/scripts/build-claim-envelope.sh --pairing-log pairing.log claim.img
```

The log must contain exactly one `Pairing claim:` line. Attach the image
read-only; after successful enrollment, detach it and remove both the envelope
and plaintext pairing log. Keep the guest's persistent root disk. Restart
without the claim disk and verify identity hashes and native service health.
The original two-argument form still accepts a file containing only the claim.

On Linux, run `scripts/check-claim-envelope.sh` to test parsing, owner-only
permissions and overwrite refusal. `scripts/check-display-runtime.sh` proves
that a display runtime missing its configured cursor is rejected before image
creation. Build the current tracked `edge` profile rather than reuse an older
runtime archive. Neither check enrolls a real peer or modifies a host disk.
