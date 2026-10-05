#!/bin/sh
# Cross-assemble an SD image on a Linux build host. Never targets a physical disk.
set -eu
pi_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$pi_dir/inputs.env"
[ "$#" -eq 6 ] || {
  echo "usage: $0 ROOTFS_TAR ROOTFS_SHA256 MYCELIUM_BINARY MYCELIUM_SHA256 OPERATOR_PUBLIC_KEY OUTPUT.img" >&2
  exit 2
}
[ "$(id -u)" -eq 0 ] || { echo 'run on Linux as root (loop image mounts)' >&2; exit 1; }
rootfs_tar=$1
rootfs_sha=$2
mycelium=$3
mycelium_sha=$4
public_key=$5
output=$6
case "$output" in /*.img) ;; *) echo 'output must be an absolute .img path' >&2; exit 1;; esac
[ ! -e "$output" ] && [ ! -e "$output.xz" ] || { echo 'refusing existing image output' >&2; exit 1; }
if [ -z "${MYCELIUM_SOURCE_REVISION:-}" ]; then
  echo 'MYCELIUM_SOURCE_REVISION is required for binary provenance' >&2
  exit 1
fi
for tool in curl sha256sum tar sfdisk losetup mkfs.vfat mkfs.ext4 mount umount useradd depmod chroot xz ssh-keygen readelf; do
  command -v "$tool" >/dev/null || { echo "missing build tool: $tool" >&2; exit 1; }
done
printf '%s  %s\n' "$rootfs_sha" "$rootfs_tar" | sha256sum -c -
printf '%s  %s\n' "$mycelium_sha" "$mycelium" | sha256sum -c -
ssh-keygen -lf "$public_key" >/dev/null
[ "$(wc -l < "$public_key")" -eq 1 ] || { echo 'exactly one operator public key required' >&2; exit 1; }
readelf -h "$mycelium" | grep -q 'Machine:.*AArch64' || { echo 'Mycelium must target AArch64' >&2; exit 1; }
if readelf -l "$mycelium" | grep -q INTERP; then echo 'Mycelium must be statically linked' >&2; exit 1; fi
work=$(mktemp -d)
loop=
cleanup() {
  mountpoint -q "$work/root/boot/firmware" && umount "$work/root/boot/firmware" || :
  mountpoint -q "$work/root" && umount "$work/root" || :
  [ -z "$loop" ] || losetup -d "$loop"
  # Keep failed build work for diagnostics; never recursively remove an input.
  echo "build staging: $work" >&2
}
trap cleanup EXIT INT TERM
curl -fL "https://codeload.github.com/raspberrypi/firmware/tar.gz/$PI_FIRMWARE_COMMIT" -o "$work/firmware.tar.gz"
printf '%s  %s\n' "$PI_FIRMWARE_SHA256" "$work/firmware.tar.gz" | sha256sum -c -
tar -xzf "$work/firmware.tar.gz" -C "$work"
firmware="$work/firmware-$PI_FIRMWARE_COMMIT"
mkdir -p "$(dirname "$output")" "$work/root"
truncate -s 2G "$output"
printf 'label: dos\nstart=2048,size=524288,type=c,bootable\nstart=526336,type=83\n' | sfdisk "$output"
loop=$(losetup --find --show --partscan "$output")
mkfs.vfat -F 32 -n FUNGOS_BOOT "${loop}p1"
mkfs.ext4 -q -L FUNGOS_ROOT "${loop}p2"
mount "${loop}p2" "$work/root"
root="$work/root"
tar -xf "$rootfs_tar" -C "$root" --numeric-owner
[ -x "$root/usr/libexec/fungos-first-contact" ] || { echo 'not a fungOS rootfs' >&2; exit 1; }
[ "$(cat "$root/etc/debian_version")" != '' ]
# Use the rootfs's signed, pinned Debian snapshot for administrative/module tools.
# A registered AArch64 binfmt interpreter is required on an amd64 build host.
cp -L /etc/resolv.conf "$root/etc/resolv.conf.build"
mv "$root/etc/resolv.conf" "$root/etc/resolv.conf.saved"
mv "$root/etc/resolv.conf.build" "$root/etc/resolv.conf"
chroot "$root" /usr/bin/apt-get update
chroot "$root" /usr/bin/apt-get install -y --no-install-recommends sudo kmod
mv "$root/etc/resolv.conf.saved" "$root/etc/resolv.conf"
mkdir -p "$root/boot/firmware" "$root/lib/modules" "$root/usr/local/bin" "$root/etc/sudoers.d"
mount "${loop}p1" "$root/boot/firmware"
for file in bootcode.bin start.elf fixup.dat kernel8.img bcm2710-rpi-3-b-plus.dtb LICENCE.broadcom COPYING.linux; do
  cp "$firmware/boot/$file" "$root/boot/firmware/"
done
cp -a "$firmware/modules/$PI_KERNEL_VERSION" "$root/lib/modules/"
depmod -b "$root" "$PI_KERNEL_VERSION"
cp "$firmware/extra/git_hash" "$root/boot/firmware/kernel-source-commit"
install -m 0644 "$pi_dir/boot/config.txt" "$pi_dir/boot/cmdline.txt" "$root/boot/firmware/"
printf 'LABEL=FUNGOS_ROOT / ext4 defaults,noatime 0 1\nLABEL=FUNGOS_BOOT /boot/firmware vfat defaults,umask=0077 0 2\n' > "$root/etc/fstab"
printf 'fungos-pi\n' > "$root/etc/hostname"
useradd --root "$root" --create-home --shell /bin/bash --groups sudo ajmwagar
owner_uid=$(awk -F: '$1 == "ajmwagar" {print $3}' "$root/etc/passwd")
owner_gid=$(awk -F: '$1 == "ajmwagar" {print $4}' "$root/etc/passwd")
install -d -m 0700 -o "$owner_uid" -g "$owner_gid" "$root/home/ajmwagar/.ssh"
install -m 0600 -o "$owner_uid" -g "$owner_gid" "$public_key" "$root/home/ajmwagar/.ssh/authorized_keys"
printf 'ajmwagar ALL=(ALL:ALL) NOPASSWD: ALL\n' > "$root/etc/sudoers.d/fungos-owner"
chmod 0440 "$root/etc/sudoers.d/fungos-owner"
chroot "$root" /usr/sbin/visudo -cf /etc/sudoers.d/fungos-owner
install -m 0755 "$mycelium" "$root/usr/local/bin/mycelium"
printf 'PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' > "$root/etc/ssh/sshd_config.d/00-fungos-pi.conf"
# No fleet claim, certificates, SSH host keys, machine identity, or daemon is cloned.
find "$root/etc/ssh" -maxdepth 1 -type f -name 'ssh_host_*' -delete
: > "$root/etc/machine-id"
find "$root/var/lib/apt/lists" -mindepth 1 -delete
find "$root/var/log" -type f -exec truncate -s 0 {} +
chroot "$root" /usr/local/bin/mycelium help > "$work/mycelium-help"
grep -q -- '--system-service' "$work/mycelium-help" || { echo 'Mycelium lacks system-service enrollment' >&2; exit 1; }
grep -q -- '--claim-file' "$work/mycelium-help" || { echo 'Mycelium lacks secure claim-file enrollment' >&2; exit 1; }
{
  echo 'target=raspberry-pi-3b-plus'
  echo 'architecture=arm64'
  echo 'profile=headless-edge'
  echo "rootfs_sha256=$rootfs_sha"
  echo "mycelium_sha256=$mycelium_sha"
  echo "mycelium_source_revision=$MYCELIUM_SOURCE_REVISION"
  echo "mycelium_build_lockfile_sha256=${MYCELIUM_LOCKFILE_SHA256:-not-recorded}"
  echo "kernel_source_revision=$(cat "$firmware/extra/git_hash")"
  echo "pi_firmware_commit=$PI_FIRMWARE_COMMIT"
  echo "pi_firmware_sha256=$PI_FIRMWARE_SHA256"
  echo "kernel=$PI_KERNEL_VERSION"
  printf 'operator_key='; ssh-keygen -lf "$public_key"
  echo 'hardware_boot=unverified'
} > "$output.manifest"
sync
umount "$root/boot/firmware"
umount "$root"
losetup -d "$loop"
loop=
xz -T 2 -6 "$output"
(cd "$(dirname "$output")" && sha256sum "$(basename "$output").xz") > "$output.xz.sha256"
chmod 0600 "$output.xz" "$output.xz.sha256" "$output.manifest"
chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$output.xz" "$output.xz.sha256" "$output.manifest"
echo "built owner-personalized image $output.xz"
