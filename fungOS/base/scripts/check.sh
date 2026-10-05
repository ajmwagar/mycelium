#!/bin/sh
set -eu

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=/dev/null
. "$base_dir/config/release.env"
packages=$($base_dir/scripts/resolve-packages.sh)
[ -n "$packages" ] || { echo "resolved package set is empty" >&2; exit 1; }
[ "$packages" = "$(printf '%s\n' "$packages" | LC_ALL=C sort -u)" ] || {
  echo "package resolution is not deterministic" >&2; exit 1;
}

for arch in amd64 arm64; do
  case "$arch" in amd64|arm64) :;; *) exit 1;; esac
done

case "$DEBIAN_SUITE" in *[!a-z0-9-]*|'') echo "invalid Debian suite" >&2; exit 1;; esac
case "$DEBIAN_SNAPSHOT" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) :;;
  *) echo "invalid Debian snapshot timestamp" >&2; exit 1;;
esac
case "$SOURCE_DATE_EPOCH" in *[!0-9]*|'') echo "invalid SOURCE_DATE_EPOCH" >&2; exit 1;; esac

while IFS= read -r package; do
  case "$package" in *[!a-z0-9+.-]*|'') echo "invalid package name: $package" >&2; exit 1;; esac
done <<EOF
$packages
EOF

for required in ca-certificates systemd systemd-sysv iproute2 systemd-resolved openssh-server; do
  printf '%s\n' "$packages" | grep -Fx "$required" >/dev/null || {
    echo "missing required package: $required" >&2; exit 1;
  }
done

if command -v shellcheck >/dev/null; then
  shellcheck "$base_dir"/scripts/*.sh "$base_dir"/rootfs/usr/libexec/fungos-*
else
  echo "warning: shellcheck not installed; syntax checks only" >&2
  for script in "$base_dir"/scripts/*.sh "$base_dir"/rootfs/usr/libexec/fungos-*; do sh -n "$script"; done
fi
echo "fungOS base declarations validated"
