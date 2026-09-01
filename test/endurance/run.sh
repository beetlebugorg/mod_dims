#!/usr/bin/env bash
#
# Runs the soak.
#
#   bash test/endurance/run.sh
#
# It starts the production server image under a CPU and memory limit, serves
# the corpus from a local origin, and drives signed requests at it for hours.
# It then reports the crashes, the memory trend, and every response that did
# not match what the request required.
#
# Build the corpus first:
#
#   bash test/endurance/corpus.sh
#
# Copyright 2026 Jeremy Collins
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

# soak      the production image, at speed, for hours
# asan      the module built with AddressSanitizer and UndefinedBehaviorSanitizer
# valgrind  one httpd process under memcheck, which reports the leaks at exit
MODE=${MODE:-soak}

CONNECTIONS=${CONNECTIONS:-16}
CPUS=${CPUS:-4}
MEM=${MEM:-2g}
INTERVAL=${INTERVAL:-15}
SEED=${SEED:-$(date +%s)}
TIMEOUT=${TIMEOUT:-120}

# /dims4/ decrypts eurl with the algorithm the server is configured for. gcm is
# what the production image sets. ecb is the module's built-in default.
EURL=${EURL:-gcm}

case "$MODE" in
    soak)     DURATION=${DURATION:-10800} ;;
    asan)     DURATION=${DURATION:-3600}; CONNECTIONS=${CONNECTIONS:-8} ;;
    valgrind) DURATION=${DURATION:-900}; CONNECTIONS=4 ;;
    *) echo "MODE must be soak, asan, or valgrind" >&2; exit 2 ;;
esac

CLIENT=soakclient
SECRET=${SECRET:-soak-secret-key}
SIGNING_KEY=${SIGNING_KEY:-0123456789abcdef0123456789abcdef}

NET=dims-soak-net
ORIGIN=dims-soak-origin
DIMS=dims-soak-server
SERVER_IMAGE=mod-dims:soak
DEBUG_IMAGE=mod-dims:soak-$MODE
CLIENT_IMAGE=mod-dims:soak-client

CORPUS="$HERE/corpus"
MANIFEST="$CORPUS/manifest.tsv"
RUN="$HERE/runs/$(date +%Y%m%d-%H%M%S)-$MODE"

log() { printf '\n=== %s ===\n' "$*" >&2; }

if [ ! -s "$MANIFEST" ]; then
    echo "No corpus. Run: bash test/endurance/corpus.sh" >&2
    exit 2
fi

mkdir -p "$RUN"

# The overlay the watermark command composites. It has to be a real image, so
# take the first one the manifest classified as decodable.
OVERLAY=$(awk -F'\t' '$4 == "image" { print $1; exit }' "$MANIFEST")
if [ -z "$OVERLAY" ]; then
    echo "The manifest has no decodable image, so the corpus is not usable." >&2
    exit 2
fi

# -- Images

log "build the images"

docker build -q -f "$ROOT/docker/Dockerfile" -t "$SERVER_IMAGE" "$ROOT" >/dev/null
docker build -q -f "$HERE/Dockerfile.client" -t "$CLIENT_IMAGE" "$ROOT" >/dev/null

if [ "$MODE" != soak ]; then
    sanitize=address,undefined
    [ "$MODE" = valgrind ] && sanitize=
    docker build -q -f "$HERE/Dockerfile.debug" \
        --build-arg DIMS_SANITIZE="$sanitize" \
        -t "$DEBUG_IMAGE" "$ROOT" >/dev/null
fi

# -- The server environment
#
# Every DIMS_ default comes from the production Dockerfile, so a variable added
# there reaches this run without an edit here. The overrides follow, and Docker
# takes the last value.

server_env=()
while IFS= read -r line; do
    entry=${line#ENV }
    value=${entry#*=}
    value=${value%\"}
    value=${value#*\"}
    [ "${entry#*=}" = "$value" ] || entry="${entry%%=*}=$value"
    server_env+=(-e "$entry")
done < <(grep '^ENV DIMS_' "$ROOT/docker/Dockerfile")

algorithm="AES/GCM/NoPadding"
[ "$EURL" = ecb ] && algorithm="AES/ECB/PKCS5Padding"

server_env+=(
    -e "DIMS_CLIENT=$CLIENT"
    -e "DIMS_SECRET=$SECRET"
    -e "DIMS_SIGNING_KEY=$SIGNING_KEY"
    -e "DIMS_WHITELIST=origin"
    -e "DIMS_ALLOW_PRIVATE_ADDRESSES=on"
    -e "DIMS_STATUS_VERBOSE=on"
    -e "DIMS_ENCRYPTION_ALGORITHM=$algorithm"
    # Port 8001 serves the metrics, so a run can be watched while it runs.
    -e "DIMS_METRICS_ENABLED=on"
    # A child that is never recycled keeps whatever it leaked, so the trend
    # below measures the module rather than the recycling interval. The
    # production default is 10000.
    -e "DIMS_MAX_CONNECTIONS_PER_CHILD=0"
)

# -- Network and origin

stop_sampler() {
    # An empty or zero pid would signal this whole process group.
    if [ -n "${SAMPLER:-}" ] && [ "$SAMPLER" -gt 0 ] 2>/dev/null; then
        kill "$SAMPLER" 2>/dev/null || true
    fi
    SAMPLER=
}

cleanup() {
    stop_sampler
    docker rm -f "$DIMS" "$ORIGIN" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$ORIGIN" "$DIMS" >/dev/null 2>&1 || true

log "start the origin"
docker run -d --name "$ORIGIN" --network "$NET" --network-alias origin \
    -v "$CORPUS/files":/usr/local/apache2/htdocs:ro \
    httpd:2.4.68 >/dev/null

log "start mod_dims ($MODE)"

if [ "$MODE" = valgrind ]; then
    docker run -d --name "$DIMS" --network "$NET" --network-alias dims \
        --cpus="$CPUS" --memory="$MEM" --memory-swap="$MEM" \
        --log-opt max-size=512m --log-opt max-file=2 \
        "${server_env[@]}" \
        -e DIMS_SERVER_LIMIT=1 -e DIMS_THREADS_PER_CHILD=1 -e DIMS_MAX_WORKERS=1 \
        --entrypoint /usr/local/bin/dims-entrypoint \
        "$DEBUG_IMAGE" \
        valgrind --tool=memcheck --leak-check=full \
            --show-leak-kinds=definite,indirect \
            --errors-for-leak-kinds=definite,indirect \
            --num-callers=40 --error-exitcode=0 \
            --suppressions=/build/mod_dims/test/valgrind/dims.supp \
            --log-file=/tmp/valgrind.log \
            /usr/local/apache2/bin/httpd -X -DFOREGROUND >/dev/null
elif [ "$MODE" = asan ]; then
    ASAN_LIB=$(docker run --rm --entrypoint cat "$DEBUG_IMAGE" /usr/local/lib/libasan.path)
    case "$ASAN_LIB" in
        /*) ;;
        *) echo "The image does not report a path for libasan.so." >&2; exit 1 ;;
    esac
    docker run -d --name "$DIMS" --network "$NET" --network-alias dims \
        --cpus="$CPUS" --memory="$MEM" --memory-swap="$MEM" \
        --log-opt max-size=512m --log-opt max-file=2 \
        "${server_env[@]}" \
        -e "LD_PRELOAD=$ASAN_LIB" \
        -e "ASAN_OPTIONS=detect_leaks=0:log_path=/tmp/asan:print_stacktrace=1:disable_coredump=1" \
        -e "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0:log_path=/tmp/ubsan" \
        "$DEBUG_IMAGE" >/dev/null
else
    docker run -d --name "$DIMS" --network "$NET" --network-alias dims \
        --cpus="$CPUS" --memory="$MEM" --memory-swap="$MEM" \
        --log-opt max-size=512m --log-opt max-file=2 \
        "${server_env[@]}" \
        "$SERVER_IMAGE" >/dev/null
fi

ready=0
for _ in $(seq 1 120); do
    if docker exec "$DIMS" /usr/local/imagemagick/bin/curl -fsS -o /dev/null \
            http://127.0.0.1:8000/dims-status/ 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done

if [ "$ready" != 1 ]; then
    echo "mod_dims did not start" >&2
    docker logs --tail 40 "$DIMS" >&2 || true
    exit 1
fi

# -- Sampling
#
# The resident memory of every process in the container, the cgroup totals, and
# the kernel OOM-kill count. A leak shows as a rising total.

SAMPLES="$RUN/samples.tsv"
printf 'time\trss_kb\tcurrent\tpeak\toom\tprocs\thttpd_pids\n' > "$SAMPLES"

#
# One read of /proc gives the resident memory, the process count, and the pid
# of every httpd. The pids matter: a child that goes and comes back is a crash,
# and the report reads that from here rather than from the log, which rotates.
#
sample_once() {
    local status rss current peak oom procs pids
    status=$(docker exec "$DIMS" sh -c 'cat /proc/[0-9]*/status 2>/dev/null' || true)
    rss=$(printf '%s' "$status" | awk '/^VmRSS:/ {s += $2} END {print s + 0}')
    procs=$(printf '%s' "$status" | grep -c '^Name:' || true)
    pids=$(printf '%s' "$status" \
            | awk '/^Name:/ {n = $2} /^Pid:/ {if (n == "httpd") printf "%s,", $2}')
    current=$(docker exec -u 0 "$DIMS" cat /sys/fs/cgroup/memory.current 2>/dev/null || echo 0)
    peak=$(docker exec -u 0 "$DIMS" cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo 0)
    oom=$(docker exec -u 0 "$DIMS" cat /sys/fs/cgroup/memory.events 2>/dev/null \
            | awk '/^oom_kill /{print $2}')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date +%s)" "${rss:-0}" "${current:-0}" \
        "${peak:-0}" "${oom:-0}" "${procs:-0}" "${pids:-}"
}

( while sleep "$INTERVAL"; do sample_once >> "$SAMPLES" 2>/dev/null || true; done ) &
SAMPLER=$!

# -- Drive it

log "drive $DURATION seconds, $CONNECTIONS connections, seed $SEED"

client_flags=()
[ "$EURL" = none ] && client_flags+=(--no-eurl)
[ "$EURL" = ecb ] && client_flags+=(--eurl-ecb)

set +e
docker run --rm --network "$NET" \
    --user "$(id -u):$(id -g)" \
    -v "$MANIFEST":/manifest.tsv:ro \
    -v "$RUN":/out \
    "$CLIENT_IMAGE" \
        --base http://dims:8000 \
        --origin http://origin:80 \
        --manifest /manifest.tsv \
        --overlay "http://origin:80/$OVERLAY" \
        --client "$CLIENT" \
        --secret "$SECRET" \
        --key "$SIGNING_KEY" \
        --seconds "$DURATION" \
        --connections "$CONNECTIONS" \
        --timeout "$TIMEOUT" \
        --seed "$SEED" \
        --failures /out/failures.ndjson \
        "${client_flags[@]}" \
    > "$RUN/soak.log" 2>&1
CLIENT_STATUS=$?
set -e

stop_sampler

sample_once >> "$SAMPLES" 2>/dev/null || true

# -- Collect

log "collect"

docker logs "$DIMS" > "$RUN/httpd.log" 2>&1 || true

if [ "$MODE" = valgrind ]; then
    # A signal stop lets valgrind print its summary before the process exits.
    # docker cp reads a stopped container, so the log survives the stop.
    docker stop --time 60 "$DIMS" >/dev/null 2>&1 || true
    docker cp "$DIMS:/tmp/valgrind.log" "$RUN/valgrind.log" 2>/dev/null || true
fi

if [ "$MODE" = asan ]; then
    docker exec "$DIMS" sh -c 'cat /tmp/asan.* /tmp/ubsan.* 2>/dev/null' \
        > "$RUN/sanitizer.log" 2>/dev/null || true
fi

# -- Report

crashes=$(grep -c "exit signal" "$RUN/httpd.log" 2>/dev/null || true)
crashes=${crashes:-0}

# How many distinct httpd processes lived during the run. The pool is fixed and
# a child is never recycled, so a number above the pool means one was replaced.
# This comes from the samples, so it survives a log the daemon rotated away.
pids_seen=$(awk -F'\t' 'NR > 1 {print $7}' "$SAMPLES" | tr ',' '\n' \
        | grep -c '[0-9]' || true)
pids_unique=$(awk -F'\t' 'NR > 1 {print $7}' "$SAMPLES" | tr ',' '\n' \
        | grep '[0-9]' | sort -u | wc -l)
pids_first=$(awk -F'\t' 'NR == 2 {print $7; exit}' "$SAMPLES" | tr ',' '\n' \
        | grep -c '[0-9]' || true)
pids_seen=${pids_seen:-0}
pids_first=${pids_first:-0}
oom=$(awk -F'\t' 'NR > 1 {v = $5} END {print v + 0}' "$SAMPLES")

# The trend, measured on the floor rather than on the samples themselves.
#
# Resident memory swings by a gigabyte between samples, because a sample
# catches whatever a worker holds part way through a decode. That swing buries
# a leak. The floor is the least memory the container held in each window, and
# a leak is what raises it.
FLOOR="$RUN/floor.tsv"
awk -F'\t' -v bucket=900 '
    NR > 1 && $2 > 0 { n++; t[n] = $1; y[n] = $2 }
    END {
        if (n < 8) { exit }
        for (b = 0; b * bucket <= t[n] - t[1]; b++) {
            low = t[1] + b * bucket
            high = low + bucket
            least = -1
            seen = 0
            for (i = 1; i <= n; i++) {
                if (t[i] >= low && t[i] < high) {
                    seen++
                    if (least < 0 || y[i] < least) { least = y[i] }
                }
            }
            if (seen > 3) { printf "%d\t%d\n", b * bucket / 60, least }
        }
    }' "$SAMPLES" > "$FLOOR"

trend=$(awk -F'\t' '
    { n++; x[n] = $1 / 60.0; y[n] = $2 }
    END {
        if (n < 4) { print "not enough samples"; exit }
        for (i = 1; i <= n; i++) { sx += x[i]; sy += y[i]; sxx += x[i] * x[i]; sxy += x[i] * y[i] }
        d = n * sxx - sx * sx
        if (d == 0) { print "not enough samples"; exit }
        printf "%.1f MiB/hour", ((n * sxy - sx * sy) / d) / 1024.0
    }' "$FLOOR")

peak_mib=$(awk -F'\t' 'NR > 1 && $4 + 0 > m {m = $4} END {printf "%.0f", m / 1048576}' "$SAMPLES")
rss_first=$(awk -F'\t' 'NR == 2 {printf "%.0f", $2 / 1024; exit}' "$SAMPLES")
rss_last=$(awk -F'\t' 'NR > 1 {v = $2} END {printf "%.0f", v / 1024}' "$SAMPLES")

{
    printf 'mod_dims soak\n'
    printf '=============\n\n'
    printf 'mode            %s\n' "$MODE"
    printf 'seed            %s\n' "$SEED"
    printf 'duration        %s seconds\n' "$DURATION"
    printf 'connections     %s\n' "$CONNECTIONS"
    printf 'limits          %s CPU, %s memory\n' "$CPUS" "$MEM"
    printf 'corpus          %s files\n' "$(( $(wc -l < "$MANIFEST") - 1 ))"
    printf '\n'
    printf 'child crashes   %s\n' "$crashes"
    printf 'httpd processes %s at the start, %s distinct over the run\n' \
        "$pids_first" "$pids_unique"
    if [ "$pids_unique" -gt "$pids_first" ]; then
        printf '                a process was replaced, so read httpd.log\n'
    fi
    printf 'oom kills       %s\n' "$oom"
    printf 'memory first    %s MiB resident\n' "$rss_first"
    printf 'memory last     %s MiB resident\n' "$rss_last"
    printf 'memory peak     %s MiB in the cgroup\n' "$peak_mib"
    printf 'memory floor    %s\n' "$trend"
    if [ -s "$FLOOR" ]; then
        printf '\nthe floor, least resident memory per 15 minutes\n'
        awk -F'\t' '{ printf "  %4d min  %6.0f MiB\n", $1, $2 / 1024 }' "$FLOOR"
    fi
    if [ "$DURATION" -lt 1800 ]; then
        printf '\n  the run is under 30 minutes, so this is warm-up, not a trend\n'
    fi
    printf '\n'
    grep '^soak ' "$RUN/soak.log" || true
    printf '\n'
    sed -n '/^mutation/,$p' "$RUN/soak.log" || true

    # What the module reported while the run went on. A resource limit and a
    # defect both end as a 500, and only this tells them apart.
    if [ -s "$RUN/httpd.log" ]; then
        printf '\nwhat the module reported\n'
        grep -ohE "(mod_dims|[Ii]magemagick) error, '[^']*'" "$RUN/httpd.log" \
            | sed "s/^ImageMagick/Imagemagick/" | sort | uniq -c | sort -rn \
            | head -20 || true
    fi

    if [ -s "$RUN/failures.ndjson" ]; then
        printf '\nfailures by kind\n'
        sed 's/.*"kind":"\([^"]*\)".*/\1/' "$RUN/failures.ndjson" \
            | sort | uniq -c | sort -rn
        printf '\nthe first five\n'
        head -5 "$RUN/failures.ndjson"
    fi

    if [ -s "${RUN}/sanitizer.log" ]; then
        printf '\nsanitizer reports\n'
        grep -c "runtime error\|ERROR: AddressSanitizer" "$RUN/sanitizer.log" || true
    fi

    if [ -s "${RUN}/valgrind.log" ]; then
        printf '\nvalgrind\n'
        grep -E "definitely lost|indirectly lost|ERROR SUMMARY" "$RUN/valgrind.log" || true
    fi
} > "$RUN/report.txt"

cat "$RUN/report.txt"

log "written to $RUN"

# A crash, an OOM kill, or a failing request fails the run.
status=0
[ "$crashes" -gt 0 ] && status=1
[ "$oom" -gt 0 ] && status=1
[ "$CLIENT_STATUS" -ne 0 ] && status=1

exit "$status"
