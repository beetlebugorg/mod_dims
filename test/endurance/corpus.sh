#!/usr/bin/env bash
#
# Downloads and builds the soak corpus. The work runs in a throwaway image, so
# the host needs only Docker.
#
#   bash test/endurance/corpus.sh
#
# The corpus lands in test/endurance/corpus/ and is ignored by git. A second
# run adds only what is missing, so an interrupted download resumes.
#
# Copyright 2026 Jeremy Collins
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMAGE=mod-dims:corpus

# How much to download. GOVDOCS counts archives of a thousand files each, at
# about 450 MB per archive. COMMONS counts individual images. DERIVE counts
# re-encodings made on this machine.
GOVDOCS=${GOVDOCS:-4}
COMMONS=${COMMONS:-600}
DERIVE=${DERIVE:-900}
MAX_BYTES=${MAX_BYTES:-6291456}
RATE=${RATE:-1}

mkdir -p "$HERE/corpus"

echo "=== build $IMAGE ===" >&2
docker build -q -f "$HERE/Dockerfile.corpus" -t "$IMAGE" "$ROOT" >/dev/null

echo "=== build the corpus ===" >&2
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e GOVDOCS="$GOVDOCS" \
    -e COMMONS="$COMMONS" \
    -e DERIVE="$DERIVE" \
    -e MAX_BYTES="$MAX_BYTES" \
    -e RATE="$RATE" \
    -e HOME=/tmp \
    -v "$HERE/corpus":/corpus \
    "$IMAGE"

echo >&2
echo "corpus at $HERE/corpus" >&2
