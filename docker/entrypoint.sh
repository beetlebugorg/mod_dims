#!/bin/sh
# Size the httpd worker pool from the container's CPU allocation, so a larger
# container scales without a configuration change. A soak test found that
# throughput peaks near one worker per vCPU, with two threads per child split
# across processes. This sets ServerLimit to half the vCPU count, at least two,
# and MaxRequestWorkers to ServerLimit times ThreadsPerChild.
#
# An explicit DIMS_SERVER_LIMIT, DIMS_THREADS_PER_CHILD, or DIMS_MAX_WORKERS
# keeps its value. The default of each is "auto".
set -e

# The effective vCPU count. nproc reports the host cores, not the container
# limit, so read the cgroup CPU quota first.
detect_vcpus() {
    if [ -r /sys/fs/cgroup/cpu.max ]; then                       # cgroup v2
        read -r quota period < /sys/fs/cgroup/cpu.max
        if [ "$quota" != max ] && [ "${period:-0}" -gt 0 ] 2>/dev/null; then
            echo $(( (quota + period - 1) / period ))
            return
        fi
    fi
    if [ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]; then          # cgroup v1
        quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
        period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
        if [ "${quota:-0}" -gt 0 ] && [ "${period:-0}" -gt 0 ] 2>/dev/null; then
            echo $(( (quota + period - 1) / period ))
            return
        fi
    fi
    nproc 2>/dev/null || echo 1
}

tpc=${DIMS_THREADS_PER_CHILD:-auto}
[ "$tpc" = auto ] && tpc=2

sl=${DIMS_SERVER_LIMIT:-auto}
if [ "$sl" = auto ]; then
    vcpus=$(detect_vcpus)
    [ "${vcpus:-0}" -ge 1 ] 2>/dev/null || vcpus=1
    sl=$(( vcpus / 2 ))
    [ "$sl" -lt 2 ] && sl=2
fi

mw=${DIMS_MAX_WORKERS:-auto}
[ "$mw" = auto ] && mw=$(( sl * tpc ))

export DIMS_SERVER_LIMIT=$sl
export DIMS_THREADS_PER_CHILD=$tpc
export DIMS_MAX_WORKERS=$mw

echo "mod_dims workers: ServerLimit=$sl ThreadsPerChild=$tpc MaxRequestWorkers=$mw" >&2

exec "$@"
