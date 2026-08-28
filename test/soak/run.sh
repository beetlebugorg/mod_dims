#!/usr/bin/env bash
# Soak test. Find the Apache MPM sizing that gives the most throughput on a
# 2 vCPU / 1 GB container with no failures.
#
# It serves pexels images locally, drives production-style command shapes with wrk, and
# for each MPM configuration records throughput, tail latency, errors, the peak
# memory, and the kernel OOM-kill count. A configuration fails if it OOM-kills a
# worker or returns any non-2xx or socket error.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NET=soak-net
ORIGIN=soak-origin
DIMS=soak-dims
IMG_DIR="$HERE/origin"
DIMS_IMAGE=mod-dims:soak
WRK_IMAGE=soak-wrk
CPUS="${CPUS:-2}"
MEM="${MEM:-1g}"
DUR="${DUR:-30s}"
WARM="${WARM:-10s}"
CONN="${CONN:-32}"
WT="${WT:-4}"

# ServerLimit ThreadsPerChild pairs to sweep. Override with SOAK_GRID, a
# semicolon-separated list, e.g. SOAK_GRID="2 2;4 1".
if [ -n "${SOAK_GRID:-}" ]; then
  IFS=";" read -ra GRID <<< "$SOAK_GRID"
else
  GRID=( "1 2" "1 3" "1 4" "1 6" "1 8" "2 2" "2 4" "1 16" "1 32" )
fi

log(){ printf '\n=== %s ===\n' "$*" >&2; }
cread(){ docker exec -u 0 "$DIMS" cat "$1" 2>/dev/null || echo 0; }

# 1. Images: three sizes of a pexels photo, downloaded once.
mkdir -p "$IMG_DIR"
declare -A PEX=(
  [big.jpg]="https://images.pexels.com/photos/1539116/pexels-photo-1539116.jpeg?auto=compress&cs=tinysrgb&w=3840"
  [medium.jpg]="https://images.pexels.com/photos/1539116/pexels-photo-1539116.jpeg?auto=compress&cs=tinysrgb&w=1920"
  [small.jpg]="https://images.pexels.com/photos/1539116/pexels-photo-1539116.jpeg?auto=compress&cs=tinysrgb&w=960"
)
for name in "${!PEX[@]}"; do
  [ -s "$IMG_DIR/$name" ] || { log "download $name"; curl -fsSL --max-time 90 -o "$IMG_DIR/$name" "${PEX[$name]}"; }
done
ls -lh "$IMG_DIR" >&2

# 1b. Signed request list. Bash signs each dims4 request, because Lua has no
# md5:  md5(expires + secret + commands + "/" + raw_url [+ encoded overlay]).
# The list mixes resize, crop, thumbnail, format, strip, and watermark shapes
# over three image sizes, and varies the width so requests miss the cache and
# decode the source. The list is cached; delete it to rebuild.
cp -f "$ROOT/test/origin/overlay.png" "$IMG_DIR/overlay.png"
CLIENT=TEST; SECRET=t3stk3y; EXPIRES=2147483647
URLS="$HERE/urls.txt"
urlenc(){ local s=$1 o= c i h; for ((i=0;i<${#s};i++)); do c=${s:i:1}; case $c in [a-zA-Z0-9]) o+=$c;; *) printf -v h '%%%02X' "'$c"; o+=$h;; esac; done; printf '%s' "$o"; }
md5f(){ printf '%s' "$1" | md5sum | cut -d' ' -f1; }
gen_urls(){
  : > "$URLS"
  local ov_enc; ov_enc=$(urlenc "http://origin/overlay.png")
  local img raw enc w cmds sig
  for img in big.jpg medium.jpg small.jpg; do
    raw="http://origin/$img"; enc=$(urlenc "$raw")
    for w in $(seq 200 5 1200); do
      for cmds in \
        "resize/${w}x/quality/85" \
        "resize/${w}x/quality/90/format/webp" \
        "crop/1600x900/resize/${w}x450/quality/85" \
        "thumbnail/${w}x300" \
        "strip/true/resize/${w}x/format/jpg/quality/80"; do
        sig=$(md5f "${EXPIRES}${SECRET}${cmds}/${raw}")
        printf '/dims4/%s/%s/%s/%s/?url=%s\n' "$CLIENT" "$sig" "$EXPIRES" "$cmds" "$enc" >> "$URLS"
      done
      cmds="resize/${w}x/watermark/0.3,0.4,se"
      sig=$(md5f "${EXPIRES}${SECRET}${cmds}/${raw}${ov_enc}")
      printf '/dims4/%s/%s/%s/%s/?url=%s&overlay=%s&_keys=overlay\n' "$CLIENT" "$sig" "$EXPIRES" "$cmds" "$enc" "$ov_enc" >> "$URLS"
    done
  done
  shuf "$URLS" -o "$URLS"
}
[ -s "$URLS" ] || { log "sign request list"; gen_urls; }
log "$(wc -l < "$URLS") signed request paths"

# 2. Build the server image and the load generator.
log "build $DIMS_IMAGE"; docker build -q -f "$ROOT/docker/Dockerfile" -t "$DIMS_IMAGE" "$ROOT" >/dev/null
log "build $WRK_IMAGE"; docker build -q -f "$HERE/Dockerfile.wrk" -t "$WRK_IMAGE" "$HERE" >/dev/null

# 3. Network and origin.
docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$ORIGIN" >/dev/null 2>&1 || true
docker run -d --name "$ORIGIN" --network "$NET" --network-alias origin \
  -v "$IMG_DIR":/usr/local/apache2/htdocs:ro httpd:2.4.68 >/dev/null

cleanup(){ docker rm -f "$DIMS" "$ORIGIN" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT

RESULTS="$HERE/results.tsv"
printf 'SL\tTPC\tworkers\treq_s\tp99_ms\tnon2xx\tsockerr\toom\tpeak_MiB\n' > "$RESULTS"

wrk_run(){ # dur
  docker run --rm --network "$NET" \
    -v "$HERE/urls.lua":/urls.lua:ro -v "$URLS":/urls.txt:ro "$WRK_IMAGE" \
    -t"$WT" -c"$CONN" -d"$1" --timeout 20s --latency -s /urls.lua http://dims:8000 2>&1
}

run_point(){
  local SL=$1 TPC=$2 MRW=$(( $1 * $2 ))
  docker rm -f "$DIMS" >/dev/null 2>&1 || true
  docker run -d --name "$DIMS" --network "$NET" --network-alias dims \
    --cpus="$CPUS" --memory="$MEM" --memory-swap="$MEM" \
    -e DIMS_CLIENT=TEST -e DIMS_SECRET=t3stk3y \
    -e DIMS_WHITELIST=origin -e DIMS_ALLOW_PRIVATE_ADDRESSES=on \
    "$DIMS_IMAGE" \
    /usr/local/apache2/bin/httpd -DFOREGROUND \
      -c "ServerLimit $SL" -c "ThreadLimit $TPC" -c "StartServers $SL" \
      -c "ThreadsPerChild $TPC" -c "MaxRequestWorkers $MRW" >/dev/null

  local ok=0
  for _ in $(seq 1 30); do
    if docker exec "$DIMS" /usr/local/imagemagick/bin/curl -fsS -o /dev/null http://127.0.0.1:8000/dims-status/ 2>/dev/null; then ok=1; break; fi
    sleep 1
  done
  [ "$ok" = 1 ] || { log "dims did not start for $SL/$TPC"; docker logs --tail 20 "$DIMS" >&2 || true; return; }

  wrk_run "$WARM" >/dev/null 2>&1 || true

  local out; out="$(wrk_run "$DUR" || true)"
  local req_s p99 non2xx sockerr peak oom
  req_s=$(printf '%s' "$out"  | awk '/Requests\/sec/{print $2}')
  p99=$(printf '%s'   "$out"  | awk '/^[[:space:]]*99%/{print $2; exit}')
  non2xx=$(printf '%s' "$out" | awk '/Non-2xx or 3xx/{print $NF}'); non2xx=${non2xx:-0}
  sockerr=$(printf '%s' "$out"| awk -F'[:,]' '/Socket errors/{c=$0; gsub(/[^0-9 ]/,"",c); n=split(c,a," "); s=0; for(i=1;i<=n;i++)s+=a[i]; print s}'); sockerr=${sockerr:-0}
  peak=$(( $(cread /sys/fs/cgroup/memory.peak) / 1048576 ))
  oom=$(cread /sys/fs/cgroup/memory.events | awk '/oom_kill /{print $2}'); oom=${oom:-0}

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$SL" "$TPC" "$MRW" "${req_s:-0}" "${p99:-?}" "$non2xx" "$sockerr" "$oom" "$peak" | tee -a "$RESULTS" >&2
}

for point in "${GRID[@]}"; do
  # shellcheck disable=SC2086
  set -- $point
  log "ServerLimit=$1 ThreadsPerChild=$2"
  run_point "$1" "$2"
done

log "results"
column -t "$RESULTS" >&2
