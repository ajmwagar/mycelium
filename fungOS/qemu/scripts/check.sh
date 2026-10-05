#!/bin/sh
set -eu

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for script in "$base_dir"/scripts/*.sh "$base_dir"/rootfs-overlay/init \
  "$base_dir"/rootfs-overlay/usr/libexec/fungos-qemu-proof; do
  sh -n "$script"
done
grep -q 'FUNGOS_QEMU_BOOT_OK' \
  "$base_dir/rootfs-overlay/usr/libexec/fungos-qemu-proof"
grep -q 'After=network-online.target' \
  "$base_dir/rootfs-overlay/usr/lib/systemd/system/fungos-qemu-proof.service"
echo "fungOS QEMU overlay validated"
