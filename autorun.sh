#!/bin/sh

die() { echo "$@"; exit 1; }

aclocal || die "Can't execute aclocal" 

if hash glibtoolize 2> /dev/null; then
  glibtoolize --automake --force || die "Can't execute glibtoolize"
else
  libtoolize --automake --force || die "Can't execute libtoolize"
fi

autoreconf -vfi || die "Can't execute autoconf"
automake --add-missing --copy --force || die "Can't execute automake"

./configure $@
