#!/bin/sh
# Downloads a release, checks it against a sha256, and unpacks it.
#
#     fetch <url> <sha256>
#
# A wrong checksum stops the build here, rather than producing an image nobody
# can reproduce.
set -eu

url="$1"
want="$2"
file="$(basename "$url")"

wget -q -O "$file" "$url"
echo "${want}  ${file}" | sha256sum -c -
tar xf "$file"
rm -f "$file"
