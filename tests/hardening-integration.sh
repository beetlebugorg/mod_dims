#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="${IMAGE_TAG:-mod-dims:hardening-itest}"
SOURCE_PORT="${SOURCE_PORT:-18080}"
SOURCE_BIND_HOST="${SOURCE_BIND_HOST:-0.0.0.0}"
BASE_DIMS_PORT="${BASE_DIMS_PORT:-18000}"
ECB_OFF_DIMS_PORT="${ECB_OFF_DIMS_PORT:-18001}"
ECB_ON_DIMS_PORT="${ECB_ON_DIMS_PORT:-18002}"
SECRET="${SECRET:-integration-secret}"

FIXTURE_PID=""

cleanup() {
  local status=$?
  if [[ -n "${FIXTURE_PID}" ]] && kill -0 "${FIXTURE_PID}" 2>/dev/null; then
    kill "${FIXTURE_PID}" || true
    wait "${FIXTURE_PID}" 2>/dev/null || true
  fi
  docker rm -f dims-itest-base dims-itest-ecb-off dims-itest-ecb-on >/dev/null 2>&1 || true
  exit "${status}"
}
trap cleanup EXIT

assert_status() {
  local expected="$1"
  local actual="$2"
  local name="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "FAIL: ${name} expected HTTP ${expected}, got ${actual}" >&2
    return 1
  fi
  echo "ok: ${name} -> ${actual}"
}

wait_http_ok() {
  local url="$1"
  local max_attempts="${2:-30}"
  local i
  for ((i = 1; i <= max_attempts; i++)); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for ${url}" >&2
  return 1
}

run_dims_container() {
  local name="$1"
  local port="$2"
  shift 2

  docker rm -f "${name}" >/dev/null 2>&1 || true
  docker run -d --name "${name}" \
    --add-host host.docker.internal:host-gateway \
    -p "127.0.0.1:${port}:8000" \
    -e DIMS_CLIENT=development \
    -e DIMS_SECRET="${SECRET}" \
    -e DIMS_WHITELIST="host.docker.internal" \
    -e DIMS_DEFAULT_IMAGE_URL="http://host.docker.internal:${SOURCE_PORT}/noimage.png" \
    -e DIMS_NO_IMAGE_URL="http://host.docker.internal:${SOURCE_PORT}/noimage.png" \
    "$@" \
    "${IMAGE_TAG}" >/dev/null

  wait_http_ok "http://127.0.0.1:${port}/dims-status/" 40
}

urlencode() {
  python3 - "$1" <<'PY'
import sys
import urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
}

request_code() {
  local url="$1"
  curl -sS -o /tmp/mod_dims_itest_body.bin -w "%{http_code}" "${url}"
}

echo "Building integration test image: ${IMAGE_TAG}"
docker build -t "${IMAGE_TAG}" -f "${ROOT_DIR}/docker/Dockerfile" "${ROOT_DIR}" >/dev/null

echo "Starting fixture server on ${SOURCE_BIND_HOST}:${SOURCE_PORT}"
python3 "${ROOT_DIR}/tests/hardening_fixture_server.py" --host "${SOURCE_BIND_HOST}" --port "${SOURCE_PORT}" &
FIXTURE_PID="$!"
wait_http_ok "http://127.0.0.1:${SOURCE_PORT}/healthz"

echo "Running hardening integration tests (base policy)"
run_dims_container "dims-itest-base" "${BASE_DIMS_PORT}" \
  -e DIMS_MAX_DOWNLOAD_BYTES=1024 \
  -e DIMS_MAX_REDIRECTS=1 \
  -e DIMS_ALLOWED_FETCH_SCHEMES="http,https"

GOOD_URL="$(urlencode "http://host.docker.internal:${SOURCE_PORT}/image.png")"
BAD_SCHEME_URL="$(urlencode "file:///etc/passwd")"
LARGE_URL="$(urlencode "http://host.docker.internal:${SOURCE_PORT}/big.bin")"
REDIRECT_URL="$(urlencode "http://host.docker.internal:${SOURCE_PORT}/redirect/3")"

code="$(request_code "http://127.0.0.1:${BASE_DIMS_PORT}/dims3/development/resize/1x1?url=${GOOD_URL}")"
assert_status 200 "${code}" "baseline small image fetch"

code="$(request_code "http://127.0.0.1:${BASE_DIMS_PORT}/dims3/development/resize/1x1?url=${BAD_SCHEME_URL}")"
assert_status 400 "${code}" "disallowed URL scheme"

code="$(request_code "http://127.0.0.1:${BASE_DIMS_PORT}/dims3/development/resize/1x1?url=${LARGE_URL}")"
assert_status 500 "${code}" "max download bytes enforcement"

code="$(request_code "http://127.0.0.1:${BASE_DIMS_PORT}/dims3/development/resize/1x1?url=${REDIRECT_URL}")"
assert_status 500 "${code}" "max redirects enforcement"

echo "Running hardening integration tests (legacy ECB disabled)"
run_dims_container "dims-itest-ecb-off" "${ECB_OFF_DIMS_PORT}" \
  -e DIMS_ENCRYPTION_ALGORITHM="AES/ECB/PKCS5Padding" \
  -e DIMS_ALLOW_LEGACY_ECB=false

KEY_HEX="$(python3 - "${SECRET}" <<'PY'
import hashlib
import sys
print(hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest()[:32])
PY
)"

ECB_PLAINTEXT="http://host.docker.internal:${SOURCE_PORT}/image.png"
ECB_ENCRYPTED="$(printf '%s' "${ECB_PLAINTEXT}" | openssl enc -aes-128-ecb -K "${KEY_HEX}" -nosalt -base64 | tr -d '\n')"
ECB_ENCRYPTED_ESCAPED="$(urlencode "${ECB_ENCRYPTED}")"

code="$(request_code "http://127.0.0.1:${ECB_OFF_DIMS_PORT}/dims3/development/resize/1x1?eurl=${ECB_ENCRYPTED_ESCAPED}")"
assert_status 500 "${code}" "legacy ECB blocked by policy"

echo "Running hardening integration tests (legacy ECB allowed)"
run_dims_container "dims-itest-ecb-on" "${ECB_ON_DIMS_PORT}" \
  -e DIMS_ENCRYPTION_ALGORITHM="AES/ECB/PKCS5Padding" \
  -e DIMS_ALLOW_LEGACY_ECB=true

code="$(request_code "http://127.0.0.1:${ECB_ON_DIMS_PORT}/dims3/development/resize/1x1?eurl=${ECB_ENCRYPTED_ESCAPED}")"
assert_status 200 "${code}" "legacy ECB allowed for compatibility"

echo "hardening-integration: ok"
