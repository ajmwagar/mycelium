#!/bin/sh
set -eu

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for script in "$base_dir"/scripts/*.sh "$base_dir"/rootfs-overlay/init \
  "$base_dir"/rootfs-overlay/usr/libexec/fungos-qemu-proof \
  "$base_dir"/rootfs-overlay/usr/libexec/fungos-mount-claim-envelope \
  "$base_dir"/rootfs-overlay/usr/lib/fungos/first-contact.d/mycelium; do
  sh -n "$script"
done
grep -q 'FUNGOS_QEMU_BOOT_OK' \
  "$base_dir/rootfs-overlay/usr/libexec/fungos-qemu-proof"
grep -q 'After=network-online.target' \
  "$base_dir/rootfs-overlay/usr/lib/systemd/system/fungos-qemu-proof.service"
grep -q -- '--claim-file /run/fungos-first-contact/claim' \
  "$base_dir/rootfs-overlay/usr/lib/fungos/first-contact.d/mycelium"
echo "fungOS QEMU overlay validated"
