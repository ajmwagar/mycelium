#!/bin/sh
# Linux integration check: disposable, unmounted claim envelopes only.
set -eu
base_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT INT TERM
umask 077
printf '%s\n' 'Pairing claim: test-only-not-a-real-invite' > "$scratch/pairing.log"
sh "$base_dir/build-claim-envelope.sh" --pairing-log "$scratch/pairing.log" "$scratch/claim.img"
actual=$(debugfs -R 'cat claim' "$scratch/claim.img" 2>/dev/null)
[ "$actual" = test-only-not-a-real-invite ]
[ "$(stat -c %a "$scratch/claim.img")" = 600 ]
if sh "$base_dir/build-claim-envelope.sh" --pairing-log "$scratch/pairing.log" "$scratch/claim.img"; then
  echo 'existing envelope was overwritten' >&2; exit 1
fi
printf '%s\n' 'no claim here' > "$scratch/missing.log"
printf '%s\n' 'Pairing claim: one' 'Pairing claim: two' > "$scratch/duplicate.log"
for kind in missing duplicate; do
  if sh "$base_dir/build-claim-envelope.sh" --pairing-log "$scratch/$kind.log" "$scratch/$kind.img"; then
    echo "accepted $kind claim" >&2; exit 1
  fi
  [ ! -e "$scratch/$kind.img" ]
done
echo 'claim envelope checks passed'
