#!/bin/sh
# Linux integration check: stale display archives must fail before image output.
set -eu
base_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT INT TERM
mkdir -p "$scratch/root" "$scratch/overlay/etc/systemd/system"
cp "$base_dir/../edge/qemu/canvas-compositor.service" "$scratch/overlay/etc/systemd/system/"
tar -cf "$scratch/stale.tar" -C "$scratch/root" .
if WORK_DIR="$scratch/work" ROOTFS_IMAGE_OUTPUT="$scratch/root.img" \
  sh "$base_dir/scripts/build-initramfs.sh" "$scratch/stale.tar" "$scratch/overlay" "$scratch/initrd" > "$scratch/output" 2>&1; then
  echo 'accepted stale display runtime' >&2; exit 1
fi
grep -q 'edge runtime is missing its configured cursor' "$scratch/output"
[ ! -e "$scratch/root.img" ] && [ ! -e "$scratch/initrd" ]
echo 'stale display runtime rejected before image creation'
