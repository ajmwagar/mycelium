#!/bin/sh
# Run locally for render, on the QEMU host for actual framebuffer capture.
set -eu
theme_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mode=${1:?usage: refresh.sh render WIDTH HEIGHT OUTPUT_DIR | capture QMP_SOCKET OUTPUT_DIR LABEL}
case "$mode" in
  prepare-rootfs)
    root=${2:?}; width=${3:?}; height=${4:?}
    case "$root" in /|'') echo 'use a staging rootfs, never the live filesystem root' >&2; exit 1;; esac
    work=$(mktemp -d "${TMPDIR:-/tmp}/fungos-theme.XXXXXX")
    trap 'rm -f "$work/render-tests" "$work/render-undergrowth" "$work/undergrowth.ppm" "$work/undergrowth.png"; rmdir "$work"' EXIT HUP INT TERM
    sh "$0" render "$width" "$height" "$work"
    asset_dir="$root/etc/fungos-edge/theme"
    config_dir="$root/var/lib/fungos-edge/config/dock/canvas/themes"
    service_dir="$root/etc/systemd/system/canvas-compositor.service.d"
    mkdir -p "$asset_dir" "$config_dir/packs" "$config_dir/selections" "$service_dir"
    install -m 0644 "$work/undergrowth.ppm" "$asset_dir/undergrowth.ppm"
    install -m 0644 "$work/undergrowth.png" "$asset_dir/undergrowth.png"
    install -m 0644 "$theme_dir/undergrowth.toml" "$config_dir/packs/undergrowth.toml"
    install -m 0644 "$theme_dir/dock.txt" "$config_dir/selections/dock.txt"
    install -m 0644 "$theme_dir/../qemu/canvas-compositor.service.d/30-undergrowth.conf" "$service_dir/30-undergrowth.conf"
    ;;
  render)
    width=${2:?}; height=${3:?}; output=${4:?}
    mkdir -p "$output"
    rustc --test "$theme_dir/render-undergrowth.rs" -o "$output/render-tests"
    "$output/render-tests"
    rustc -O "$theme_dir/render-undergrowth.rs" -o "$output/render-undergrowth"
    "$output/render-undergrowth" "$width" "$height" "$output/undergrowth.ppm"
    ffmpeg -v error -y -i "$output/undergrowth.ppm" -frames:v 1 "$output/undergrowth.png"
    ;;
  capture|capture-vnc)
    socket=${2:?}; output=${3:?}; label=${4:?}
    case "$label" in *[!a-z0-9-]*|'') echo 'label must be lowercase ASCII identifier' >&2; exit 1;; esac
    mkdir -p "$output"
    output=$(CDPATH= cd -- "$output" && pwd)
    source_commit=${FUNGOS_SOURCE_COMMIT:-$(git -C "$theme_dir" rev-parse HEAD)}
    if [ "$mode" = capture ]; then
      rustc -O "$theme_dir/capture-qmp.rs" -o "$output/capture-qmp"
      timeout 20 "$output/capture-qmp" "$socket" "$output/$label.ppm"
    else
      rustc -O "$theme_dir/capture-vnc.rs" -o "$output/capture-vnc"
      "$output/capture-vnc" "$socket" "$output/$label.ppm"
    fi
    ffmpeg -v error -y -i "$output/$label.ppm" -frames:v 1 "$output/$label.png"
    {
      printf 'kind=actual-qemu-framebuffer\ncaptured_at='; date -u '+%Y-%m-%dT%H:%M:%SZ'
      printf 'capture_transport=%s\nendpoint=%s\n' "$mode" "$socket"
      printf 'source_commit=%s\n' "$source_commit"
      sha256sum "$output/$label.png"
    } > "$output/$label.provenance.txt"
    ;;
  *) echo 'unknown mode' >&2; exit 1;;
esac
