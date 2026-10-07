#!/bin/sh
set -eu

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for script in "$base_dir"/scripts/*.sh "$base_dir"/rootfs-overlay/init \
  "$base_dir"/rootfs-overlay/usr/libexec/fungos-qemu-proof \
  "$base_dir"/rootfs-overlay/usr/libexec/fungos-mount-claim-envelope \
  "$base_dir"/rootfs-overlay/usr/lib/fungos/first-contact.d/mycelium \
  "$base_dir"/rootfs-overlay/usr/local/bin/mycelium; do
  sh -n "$script"
done
grep -q 'FUNGOS_QEMU_BOOT_OK' \
  "$base_dir/rootfs-overlay/usr/libexec/fungos-qemu-proof"
grep -q 'After=network-online.target' \
  "$base_dir/rootfs-overlay/usr/lib/systemd/system/fungos-qemu-proof.service"
grep -q -- '--claim-file /run/fungos-first-contact/claim' \
  "$base_dir/rootfs-overlay/usr/lib/fungos/first-contact.d/mycelium"
grep -q 'ConditionPathExists=/run/fungos-first-contact/first-contact.env' \
  "$base_dir/rootfs-overlay/etc/systemd/system/fungos-first-contact.service.d/10-qemu-claim-envelope.conf"
grep -q 'install -m 0600 "$mountpoint/first-contact.env" "$staging/first-contact.env"' \
  "$base_dir/rootfs-overlay/usr/libexec/fungos-mount-claim-envelope"
grep -q "trap .*umount.*EXIT" \
  "$base_dir/rootfs-overlay/usr/libexec/fungos-mount-claim-envelope"

# Exercise dispatch through the managed path, including argument boundaries and
# a replaced executable. No enrollment or machine-wide binary is changed.
scratch=$(mktemp -d)
trap 'rm -f "$scratch/bin/mycelium"; rmdir "$scratch/bin" "$scratch"' EXIT INT TERM
mkdir "$scratch/bin"
ln -s /usr/bin/printf "$scratch/bin/mycelium"
actual=$(MYCELIUM_HOME="$scratch" sh "$base_dir/rootfs-overlay/usr/local/bin/mycelium" \
  '%s\n' 'argument with spaces' --json)
expected=$(printf '%s\n' 'argument with spaces' --json)
[ "$actual" = "$expected" ] || { echo "managed CLI lost arguments" >&2; exit 1; }
rm -f "$scratch/bin/mycelium"
ln -s /usr/bin/false "$scratch/bin/mycelium"
if MYCELIUM_HOME="$scratch" sh "$base_dir/rootfs-overlay/usr/local/bin/mycelium"; then
  echo "managed CLI ignored replacement" >&2
  exit 1
fi
echo "fungOS QEMU overlay validated"
