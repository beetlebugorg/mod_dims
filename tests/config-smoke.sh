#!/usr/bin/env bash
set -euo pipefail

grep -Eq "^DimsSignatureAlgorithm[[:space:]]+legacy-md5$" examples/dims.conf
grep -Eq "^DimsStrictValidation[[:space:]]+false$" examples/dims.conf
grep -Eq "^DimsEncryptionAlgorithm[[:space:]]+AES/GCM/NoPadding$" examples/dims.conf
grep -Eq "^DimsAllowLegacyEcb[[:space:]]+false$" examples/dims.conf
grep -Eq "^DimsAllowedFetchSchemes[[:space:]]+http,https$" examples/dims.conf
grep -Eq "^DimsSignatureAlgorithm[[:space:]]+\\$\\{DIMS_SIGNATURE_ALGORITHM\\}$" docker/dims.conf
grep -Eq "^DimsStrictValidation[[:space:]]+\\$\\{DIMS_STRICT_VALIDATION\\}$" docker/dims.conf
grep -Eq "^DimsEncryptionAlgorithm[[:space:]]+\\$\\{DIMS_ENCRYPTION_ALGORITHM\\}$" docker/dims.conf
grep -Eq "^DimsAllowLegacyEcb[[:space:]]+\\$\\{DIMS_ALLOW_LEGACY_ECB\\}$" docker/dims.conf
grep -Eq "^DimsAllowedFetchSchemes[[:space:]]+\\$\\{DIMS_ALLOWED_FETCH_SCHEMES\\}$" docker/dims.conf

echo "config-smoke: ok"
