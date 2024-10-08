#!/bin/sh
#
# setup/re-init the autoconf files on a raw checkout
# minimalistic version
#

fail() {
    echo "FAIL: $@" >&2
    exit 1
}

# check location

if [ ! -f ./configure.ac ]; then
    fail "$0 needs to run fromt the top level directory where configure.ac resides."
fi

# check tools we need

AUTOCONF="${AUTOCONF:-autoconf}"
AUTORECONF="${AUTORECONF:-autoreconf}"
AUTOMAKE="${AUTOMAKE:-automake}"

for tool in "$AUTOCONF" "$AUTORECONF" "$AUTOMAKE"; do
    type "$tool" 2>&1 >/dev/null
    if test $? -ne 0; then
        fail "need ${tool} installed."
    fi
done

for i in .configured .deps compile aclocal.m4 autom4te.cache \
    autoscan.log config.guess config.status config.sub \
    config.h config.h.in config.h.in~ configure configure.scan \
    depcomp install-sh libtool ltmain.sh missing stamp-h1 \
    Makefile.in Makefile \
    src/Makefile.in src/Makefile \
    test/Makefile.in test/Makefile \
    ; do
    test -z "$i" || rm -rf "$i" 
done

"$AUTORECONF" -i || exit $?
"$AUTOMAKE" || exit $?
"$AUTOCONF" || exit $?01

./configure $@