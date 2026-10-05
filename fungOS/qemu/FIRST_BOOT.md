# First fungOS Genesis boot evidence

Date: 2026-10-04 (America/Los_Angeles)
Executor: Agora-One, QEMU/KVM 10.2.1, OVMF UEFI
Guest identity: `fungos-qemu-01`, `52:54:00:12:34:56`

The first isolated boot completed through this path:

1. An isolated `genesis0` Linux bridge supplied a lease from a test-only DHCP
   instance. It had no physical uplink.
2. The reviewed Genesis dnsmasq plan answered only as ProxyDHCP for the selected
   MAC.
3. OVMF fetched `ipxe-amd64.efi`, the only file in the TFTP root.
4. iPXE fetched `bootstrap.ipxe` and the MAC-specific script from `genesisd`.
5. `genesisd` verified and served the kernel and initramfs by SHA-256.
6. QEMU attached a disposable sparse 8 GiB qcow2 system disk.
7. The pinned Debian fungOS base entered systemd and emitted
   `FUNGOS_QEMU_BOOT_OK` at 1.783 seconds of kernel time.

## Artifact identities

| Artifact | SHA-256 |
| --- | --- |
| iPXE amd64 UEFI loader | `a44ca2737f3c534be9635d828b94035871ba5e3d777d41a6e86e3a5f099c7e5d` |
| Agora Ubuntu test kernel | `7efd88a7facf80874d781ccb2c2421f0aaaa575e3b94760430619e826f490117` |
| fungOS base root filesystem | `b379f44e98603c8be9363d90c3d4fd05d3e6073dabb091ed9019f24650f097dd` |
| fungOS QEMU initramfs | `fefc088a6f2f765b2d4d5d59fca4cee37b50344fecd1441837e8bde129d768c6` |

The final adapter verification satisfied all five postconditions: exact
rendered dnsmasq configuration, ProxyDHCP-only ranges, one-file TFTP allowlist,
and exact bootstrap and machine-specific HTTP files. The retained observation
digest on Agora-One is
`8930913f2957cc56a7ce07dc008a626ac9f12b55b57a2b30008e0e5ed881e9fd`.
The final retained serial-log digest, including the qcow2-backed run, is
`f32acebbe72238f97c46216bb0be9dd2c49e4abd36e5fb6cddbfeea009c162e9`.

The guest had discovered `eth0` but it was still down when the proof service
ran. Network convergence after userspace handoff remains a separate acceptance
condition for the immediate Mycelium-enrollment slice; preboot networking and
all Genesis transports were proven here.

## Userspace network revalidation

The stricter profile was rebuilt with explicit `udev` and `kmod` dependencies
and booted again on 2026-10-04. Its base filesystem digest was
`e8ea565ecc064ce49321a202a0f132ca40dc524fc86149a741cd7ed2dd2c63f5` and
its initramfs digest was
`df5bb4f2ad56996ea5d26d0222888c29198e3029be24d5f5ba2ab008c424c23a`.
The guest renamed the VirtIO interface to `enp0s2`, acquired
`192.0.2.112/24`, and emitted both required markers:

```text
FUNGOS_QEMU_NETWORK_OK address=192.0.2.112/24
FUNGOS_QEMU_BOOT_OK
```

This supersedes the earlier network caveat. A profile without a global
userspace address now fails rather than producing a successful proof marker.

## Cleanup result

The QEMU process, both isolated dnsmasq processes, `genesisd`, `genesis-tap`,
and `genesis0` were stopped or removed after evidence capture. The disposable
qcow2 disk and other build and boot evidence remain under
`~/.cache/fungos-build` and `~/.cache/fungos-qemu` on Agora-One. No household
interface, DHCP service, or existing Shroud bridge was modified.
