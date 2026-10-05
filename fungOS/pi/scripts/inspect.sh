#!/bin/sh
# Read-only image inspection is not a hardware boot test.
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 IMAGE.img" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'run as root on Linux' >&2; exit 1; }
image=$1
[ -f "$image" ] || { echo 'image must be a regular file, not a disk' >&2; exit 1; }
work=$(mktemp -d)
loop=
cleanup() {
  mountpoint -q "$work/root/boot/firmware" && umount "$work/root/boot/firmware" || :
  mountpoint -q "$work/root" && umount "$work/root" || :
  [ -z "$loop" ] || losetup -d "$loop"
  rmdir "$work/root" "$work"
}
trap cleanup EXIT INT TERM
mkdir "$work/root"
loop=$(losetup --find --show --read-only --partscan "$image")
fsck.fat -n "${loop}p1"
e2fsck -fn "${loop}p2"
mount -o ro,noload "${loop}p2" "$work/root"
root="$work/root"
mount -o ro "${loop}p1" "$root/boot/firmware"
for file in kernel8.img bcm2710-rpi-3-b-plus.dtb bootcode.bin start.elf fixup.dat config.txt cmdline.txt LICENCE.broadcom COPYING.linux kernel-source-commit; do
  [ -s "$root/boot/firmware/$file" ] || { echo "missing boot input: $file" >&2; exit 1; }
done
[ ! -s "$root/etc/machine-id" ] || { echo 'cloned machine ID' >&2; exit 1; }
[ -z "$(find "$root/etc/ssh" -maxdepth 1 -name 'ssh_host_*' -print)" ] || { echo 'cloned SSH host key' >&2; exit 1; }
[ ! -e "$root/var/lib/mycelium/pki/node-key.pem" ] || { echo 'cloned mesh identity' >&2; exit 1; }
awk -F: '$1 == "root" && $2 !~ /^[!*]/ {exit 1}' "$root/etc/shadow"
awk -F: '$1 == "ajmwagar" && $2 !~ /^[!*]/ {exit 1}' "$root/etc/shadow"
ssh-keygen -lf "$root/home/ajmwagar/.ssh/authorized_keys"
[ "$(stat -c %a "$root/home/ajmwagar/.ssh")" = 700 ]
[ "$(stat -c %a "$root/home/ajmwagar/.ssh/authorized_keys")" = 600 ]
grep -q '^PermitRootLogin no$' "$root/etc/ssh/sshd_config.d/00-fungos-pi.conf"
grep -q '^PasswordAuthentication no$' "$root/etc/ssh/sshd_config.d/00-fungos-pi.conf"
grep -q '^KbdInteractiveAuthentication no$' "$root/etc/ssh/sshd_config.d/00-fungos-pi.conf"
grep -q '^arm_64bit=1$' "$root/boot/firmware/config.txt"
grep -q 'root=/dev/mmcblk0p2.*rootwait' "$root/boot/firmware/cmdline.txt"
if [ -z "$(find "$root/lib/modules" -name 'lan78xx.ko*' -print)" ]; then
  grep -q 'drivers/net/usb/lan78xx.ko' "$root"/lib/modules/*/modules.builtin || {
    echo 'missing Pi 3B+ Ethernet driver (module or built-in)' >&2; exit 1;
  }
fi
chroot "$root" /usr/sbin/visudo -cf /etc/sudoers.d/fungos-owner
chroot "$root" /usr/local/bin/mycelium help | grep -- '--claim-file'
echo 'Pi 3B+ boot layout, filesystems, native module set and secure bootstrap inspected; hardware boot UNVERIFIED'
