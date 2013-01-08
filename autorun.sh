#!/bin/sh

die() { echo "$@"; exit 1; }

aclocal || die "Can't execute aclocal" 

command -v glibtoolize &> /dev/null
if [ $? -eq 0 ]; then
  glibtoolize --automake --force || die "Can't execute glibtoolize"
else
  libtoolize --automake --force || die "Can't execute libtoolize"
fi

autoconf || die "Can't execute autoconf"
automake --add-missing --copy --force || die "Can't execute automake"

# don't execute configure, because we use %configure macro in the spec file
# ./configure
