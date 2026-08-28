#!/bin/bash
#
# Runs httpd under valgrind, drives the module over a representative set of
# requests, stops httpd so valgrind reports at exit, and fails when a block
# allocated in module code is definitely lost.
#
# The unit sanitizers cover the operations. This covers the request path that
# only runs inside httpd: the handler, the fetch, the pipeline, and cleanup.
# ImageMagick frees its process-global state at MagickWandTerminus, which the
# signal stop skips, so that state shows as lost and dims.supp holds it.
#
# Copyright 2026 Jeremy Collins
# SPDX-License-Identifier: Apache-2.0

set -u

ROOT=/build/mod_dims
SUPP="$ROOT/test/valgrind/dims.supp"
LOG=${VG_LOG:-/tmp/valgrind.log}
HTTPD=/usr/local/apache2/bin/httpd
BASE=http://127.0.0.1:8000
ORIGIN=http%3A%2F%2Forigin%3A8080

supp_arg=""
[ -f "$SUPP" ] && supp_arg="--suppressions=$SUPP"

valgrind --tool=memcheck --leak-check=full \
    --show-leak-kinds=definite,indirect \
    --errors-for-leak-kinds=definite,indirect \
    --num-callers=40 --error-exitcode=0 $supp_arg \
    --gen-suppressions=all --log-file="$LOG" \
    "$HTTPD" -X -DFOREGROUND >/tmp/httpd.out 2>&1 &
VG=$!

# httpd starts slowly under valgrind because ImageMagick loads every coder.
ready=0
for i in $(seq 1 180); do
    if wget -q -O /dev/null "$BASE/dims-status/" 2>/dev/null; then ready=1; break; fi
    kill -0 $VG 2>/dev/null || break
    sleep 1
done
if [ "$ready" != 1 ]; then
    echo "httpd did not become ready under valgrind"
    cat /tmp/httpd.out
    kill -TERM $VG 2>/dev/null
    exit 1
fi

# A /dims4/ signature is the first six characters of md5(expires+secret+commands+url).
sign4() {
    printf '%s' "2147483647t3stk3y$1/$2" | md5sum | cut -c1-6
}

echo "--- driving requests ---"
paths=(
    "/dims3/TEST/resize/100x100/?url=$ORIGIN%2Fgrid.png"
    "/dims3/TEST/crop/50x50/?url=$ORIGIN%2Fgrid.png"
    "/dims3/TEST/thumbnail/80x80/?url=$ORIGIN%2Fgrid.png"
    "/dims3/TEST/resize/120x120/quality/70/format/webp/?url=$ORIGIN%2Fgrid.png"
    "/dims3/TEST/rotate/90/?url=$ORIGIN%2Fgrid.png"
    "/dims3/TEST/watermark/1.0,0.5,se/?url=$ORIGIN%2Fgrid.png&overlay=$ORIGIN%2Foverlay.png"
    "/dims3/TEST/watermark/1.0,0.5,nw/?url=$ORIGIN%2Fgrid.png&overlay=$ORIGIN%2Foverlay.png"
    "/dims3/TEST/resize/100x100/?url=$ORIGIN%2Fsample.svg"
    "/dims3/TEST/resize/100x100/?url=$ORIGIN%2Fmissing.png"
    "/dims-status/"
)
for p in "${paths[@]}"; do
    code=$(wget -q -O /dev/null -S "$BASE$p" 2>&1 | awk '/HTTP\//{c=$2} END{print c}')
    echo "  $code  $p"
done

# One signed /dims4/ request, to reach the signature path.
sig=$(sign4 "resize/100x100" "http://origin:8080/grid.png")
p="/dims4/TEST/$sig/2147483647/resize/100x100/?url=$ORIGIN%2Fgrid.png"
code=$(wget -q -O /dev/null -S "$BASE$p" 2>&1 | awk '/HTTP\//{c=$2} END{print c}')
echo "  $code  $p"

sleep 1
echo "--- stopping httpd ---"
kill -TERM $VG 2>/dev/null
wait $VG 2>/dev/null

echo "=== valgrind leak summary ==="
grep -E "definitely lost|indirectly lost|possibly lost|still reachable|ERROR SUMMARY" "$LOG"

# A module leak is a definitely lost block whose allocation frame is in module
# code, that is, the frame right after malloc names a module function or file.
# A block ImageMagick allocated through a module call, such as NewMagickWand or
# MagickReadImageBlob, is owned by ImageMagick's process-global state and freed
# at MagickWandTerminus, which the signal stop skips, so it is not counted.
module_re="dims_|svgguard|netguard|overlay_cache|handler[.]c|curl[.]c|module[.]c|status[.]c|profile[.]c|encryption[.]c|signature[.]c|url[.]c"
scan='
    /are definitely lost/{cap=1; an=0; found=0; buf=$0"\n"; next}
    cap{ buf=buf$0"\n"
         if($0 ~ /at 0x[0-9A-F]+: (malloc|calloc|realloc|posix_memalign|operator new)/){ an=1; next }
         if(an==1){ if($0 ~ re) found=1; an=0 }
         if($0 ~ /^==[0-9]+== *$/){ if(found){ c++; printf "%s", buf } cap=0 } }
    END{ print "COUNT " c+0 > "/dev/stderr" }'

report=$(awk -v re="$module_re" "$scan" "$LOG" 2> "$LOG.count")
module_leaks=$(sed -n 's/^COUNT //p' "$LOG.count")

echo "definitely lost blocks allocated in module code: ${module_leaks:-0}"
if [ "${module_leaks:-0}" -gt 0 ]; then
    echo "FAIL: a module allocation was definitely lost. Full report at $LOG"
    echo "$report"
    exit 1
fi
echo "PASS: no module allocation was definitely lost"
