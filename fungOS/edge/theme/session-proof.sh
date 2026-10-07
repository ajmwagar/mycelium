#!/bin/sh
# Genuine session evidence shown by the actual Wayland terminal, not a mock UI.
printf '\033]0;fungOS / native Canvas\007'
hostname
uname -r
printf '\n'
systemctl --no-pager --plain is-active canvas-compositor canvas canvas-edge unibus-router mycelium
printf '\n'
ls /etc/fungos-edge
printf '\n'
exec /bin/sh
