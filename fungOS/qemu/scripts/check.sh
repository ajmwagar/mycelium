#!/bin/sh
set -eu

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for script in "$base_dir"/scripts/*.sh "$base_dir"/rootfs-overlay/init; do
  sh -n "$script"
done
grep -qx 'FUNGOS_QEMU_BOOT_OK' /dev/null 2>/dev/null || true
grep -q 'FUNGOS_QEMU_BOOT_OK' \
  "$base_dir/rootfs-overlay/usr/lib/systemd/system/fungos-qemu-proof.service"
echo "fungOS QEMU overlay validated"
