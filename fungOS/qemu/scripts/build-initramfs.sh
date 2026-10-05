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
if [ -n "${MYCELIUM_BINARY:-}" ]; then
  [ -x "$MYCELIUM_BINARY" ] || {
    echo "MYCELIUM_BINARY is not executable: $MYCELIUM_BINARY" >&2
    exit 1
  }
  install -m 0755 "$MYCELIUM_BINARY" "$work_dir/usr/local/bin/mycelium"
fi
cp "$busybox" "$work_dir/busybox"
chmod 0755 "$work_dir/init"
mkdir -p "$work_dir/etc/systemd/system/multi-user.target.wants"
ln -sfn /usr/lib/systemd/system/fungos-qemu-proof.service \
  "$work_dir/etc/systemd/system/multi-user.target.wants/fungos-qemu-proof.service"

(
  cd "$work_dir"
  find . -xdev -print0 \
    | LC_ALL=C sort -z \
    | cpio --null --create --format=newc --owner=0:0
) | gzip -n -9 > "$output"

echo "built $output"
