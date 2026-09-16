#!/bin/sh
# Precompile every XKB layout and variant known to xkb-data into the binary
# console keymap that wisp-init loads (cmd/wisp-init/keymap.go): ckbcomp
# (console-setup) renders the layout as a console keymap, `loadkeys -b -u` (kbd)
# as the kernel's own table encoding. The bytes depend only on the versions of
# xkb-data, console-setup and kbd, which the package build pins, so a wisp
# release ships a fixed set and the file an initramfs carries is a byte copy
# of a file in the wisp package.
#
#   tools/mkkeymaps.sh <outdir> [<base.lst>]
#
# Names: <layout>.bkmap and <layout>+<variant>.bkmap. XKB options and models are
# not applied; the model is ckbcomp's default (pc105).
set -eu
out=$1
lst=${2:-/usr/share/X11/xkb/rules/base.lst}
mkdir -p "$out"
awk '/^! layout/{s=1;next} /^! variant/{s=2;next} /^!/{s=0}
     s==1&&NF{print $1} s==2&&NF{l=$2; sub(":$","",l); print l"+"$1}' "$lst" \
  | grep -v '^custom' | sort -u > "$out/.list"
rm -f "$out/.failed"
xargs -P "$(nproc)" -I{} sh -c '
  n="{}"; l="${n%%+*}"; v=""; case "$n" in *+*) v="${n#*+}";; esac
  if [ -n "$v" ]; then ckbcomp -layout "$l" -variant "$v"; else ckbcomp -layout "$l"; fi 2>/dev/null > "'"$out"'/$n.kmap" \
    && loadkeys -b -u "'"$out"'/$n.kmap" > "'"$out"'/$n.bkmap" 2>/dev/null \
    && [ -s "'"$out"'/$n.bkmap" ] || echo "$n" >> "'"$out"'/.failed"
  rm -f "'"$out"'/$n.kmap"' < "$out/.list"
if [ -e "$out/.failed" ]; then
  echo "mkkeymaps: failed: $(tr '\n' ' ' < "$out/.failed")" >&2
  exit 1
fi
n=$(wc -l < "$out/.list"); rm -f "$out/.list"
echo "mkkeymaps: $n keymaps in $out"
