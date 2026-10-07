#!/bin/sh
set -eu

pairing_log=false
if [ "${1:-}" = "--pairing-log" ]; then
  pairing_log=true
  shift
fi
[ "$#" -eq 2 ] || {
  echo "usage: $0 [--pairing-log] CLAIM_FILE OUTPUT_IMAGE" >&2
  exit 2
}
claim=$1
output=$2

[ -r "$claim" ] || { echo "claim file is not readable: $claim" >&2; exit 1; }
command -v mkfs.ext4 >/dev/null || { echo "mkfs.ext4 is required" >&2; exit 1; }

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT INT TERM
umask 077
if [ "$pairing_log" = true ]; then
  # Consume generated CLI output without echoing its one-use secret. Refuse
  # absent/ambiguous claims rather than selecting an arbitrary line.
  awk '/^Pairing claim: / { count++; sub(/^Pairing claim: /, ""); print }
       END { if (count != 1) exit 1 }' "$claim" > "$work_dir/claim" || {
    echo "pairing log must contain exactly one claim" >&2
    exit 1
  }
else
  install -m 0600 "$claim" "$work_dir/claim"
fi
printf '%s\n' 'PROFILE=fungos-qemu' > "$work_dir/first-contact.env"
chmod 0600 "$work_dir/first-contact.env"

mkdir -p "$(dirname "$output")"
[ ! -e "$output" ] || { echo "refusing existing envelope: $output" >&2; exit 1; }
truncate -s 8M "$output"
mkfs.ext4 -q -F -L FUNGOS_CLAIM -d "$work_dir" "$output"
chmod 0600 "$output"
echo "built one-time claim envelope $output"
