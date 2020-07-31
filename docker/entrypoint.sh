#!/bin/bash

PKG_VERSION="$DIMS_VERSION"
PKG_LICENSE="Apache 2.0"
PKG_NAME="mod-dims"
PKG_MAINTAINER="jeremy.collins@beetlebug.org"

cd build || exit

git clone -b release/"$DIMS_VERSION" https://github.com/beetlebugorg/mod_dims

cd mod_dims || exit
./autorun.sh --with-apxs=$(command -v apxs2)
make

checkinstall \
    --maintainer=$PKG_MAINTAINER \
    --pkgrelease="$LSB_RELEASE" \
    --pkglicense="$PKG_LICENSE" \
    --pkgversion="$PKG_VERSION" \
    --pkgname=$PKG_NAME \
    --requires "$PKG_REQUIRES" \
    --default

mv *.deb ../
cd ..

rm -rf mod_dims