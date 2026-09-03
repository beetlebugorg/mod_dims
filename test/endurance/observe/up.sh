#!/usr/bin/env bash
#
# Starts Prometheus and Grafana against a running soak.
#
#   bash test/endurance/observe/up.sh
#
# Copyright 2026 Jeremy Collins
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if ! docker network inspect dims-soak-net >/dev/null 2>&1; then
    echo "dims-soak-net is missing. Start the soak first:" >&2
    echo "  bash test/endurance/run.sh" >&2
    exit 1
fi

docker compose -f "$HERE/compose.yaml" up -d

address=$(ip -4 addr show scope global 2>/dev/null \
    | grep -oP 'inet \K[\d.]+' | head -1)

echo
echo "Grafana:    http://${address:-localhost}:3000/d/mod-dims-soak/mod-dims"
echo "Prometheus: docker compose -f $HERE/compose.yaml exec prometheus wget -qO- localhost:9090/-/healthy"
