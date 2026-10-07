#!/bin/sh
set -eu

[ "$#" -eq 3 ] || {
  echo "usage: $0 ROOTFS_TAR OVERLAY_DIR OUTPUT_INITRD" >&2
  exit 2
}
rootfs_tar=$1
overlay_dir=$2
output=$3

[ -r "$rootfs_tar" ] || { echo "root filesystem is not readable: $rootfs_tar" >&2; exit 1; }
[ -d "$overlay_dir" ] || { echo "overlay is not a directory: $overlay_dir" >&2; exit 1; }
command -v cpio >/dev/null || { echo "cpio is required" >&2; exit 1; }
command -v gzip >/dev/null || { echo "gzip is required" >&2; exit 1; }
busybox=${BUSYBOX:-/usr/bin/busybox}
[ -x "$busybox" ] || { echo "a static busybox is required: $busybox" >&2; exit 1; }

work_dir=${WORK_DIR:-"$(dirname "$output")/.initramfs-work"}
[ ! -e "$work_dir" ] || { echo "refusing non-clean work directory: $work_dir" >&2; exit 1; }
mkdir -p "$work_dir" "$(dirname "$output")"
trap 'rm -rf "$work_dir"' EXIT INT TERM

tar -xf "$rootfs_tar" -C "$work_dir"
cp -a "$overlay_dir/." "$work_dir/"
# First boot establishes a fresh machine identity; subsequent disk boots retain it.
rm -f "$work_dir/etc/machine-id"
if [ -n "${MYCELIUM_BINARY:-}" ]; then
  [ -x "$MYCELIUM_BINARY" ] || {
    echo "MYCELIUM_BINARY is not executable: $MYCELIUM_BINARY" >&2
    exit 1
  }
  mkdir -p "$work_dir/usr/libexec" "$work_dir/usr/local/bin"
  install -m 0755 "$MYCELIUM_BINARY" "$work_dir/usr/libexec/mycelium-bootstrap"
  install -m 0755 "$(dirname "$0")/../rootfs-overlay/usr/local/bin/mycelium" \
    "$work_dir/usr/local/bin/mycelium"
fi
cp "$busybox" "$work_dir/busybox"
chmod 0755 "$work_dir/init"
mkdir -p "$work_dir/etc/systemd/system/multi-user.target.wants"
ln -sfn /usr/lib/systemd/system/fungos-qemu-proof.service \
  "$work_dir/etc/systemd/system/multi-user.target.wants/fungos-qemu-proof.service"

if [ -n "${ROOTFS_IMAGE_OUTPUT:-}" ]; then
  [ ! -e "$ROOTFS_IMAGE_OUTPUT" ] || {
    echo "refusing to overwrite root disk: $ROOTFS_IMAGE_OUTPUT" >&2
    exit 1
  }
  command -v mke2fs >/dev/null || { echo "mke2fs is required" >&2; exit 1; }
  # Match cpio's forced root ownership; copied overlays may belong to the builder.
  chown -R 0:0 "$work_dir"
  # A fresh artifact only: never format an attached host disk or existing image.
  mke2fs -q -t ext4 -b 4096 -L FUNGOS_ROOT -d "$work_dir" \
    "$ROOTFS_IMAGE_OUTPUT" 2097152
fi

(
  cd "$work_dir"
  find . -xdev -print0 \
    | LC_ALL=C sort -z \
    | cpio --null --create --format=newc --owner=0:0
) | gzip -n -9 > "$output"

echo "built $output"
