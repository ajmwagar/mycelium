#!/bin/sh
# A real source inspection in a second native terminal, no fabricated editor.
printf '\033]0;Undergrowth / source\007'
sed -n '1,22p' /etc/fungos-edge/theme/render-undergrowth.rs
printf '\n'
exec /bin/sh
