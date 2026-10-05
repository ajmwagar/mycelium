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
`FUNGOS_QEMU_BOOT_OK` to the serial console after `network-online.target`.
The initramfs builder adds the host's statically linked BusyBox only as the
early `/init` interpreter; it is not installed into the fungOS base image.

All runtime state belongs under a caller-selected scratch directory. The
cleanup runbook removes only the named bridge, TAP, dnsmasq processes, and
scratch directory created for the experiment.

The checked-in `lease-dnsmasq.conf` is intentionally lease-only and may be
used only on the isolated `genesis0` bridge. The Genesis-rendered second
configuration remains ProxyDHCP-only and machine-scoped.
