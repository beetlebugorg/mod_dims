#!/bin/sh

die() { echo "$@"; exit 1; }

aclocal || die "Can't execute aclocal" 
#autoheader || die "Can't execute autoheader"

if test -f /usr/bin/glibtoolize  ; then
  glibtoolize --automake --force || die "Can't execute glibtoolize"
else
  libtoolize --automake --force || die "Can't execute libtoolize"
fi
  
automake --add-missing --copy --force || die "Can't execute automake"
autoconf || die "Can't execute autoconf"
