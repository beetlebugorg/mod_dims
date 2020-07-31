#!/bin/bash

PKG_VERSION="$DIMS_VERSION"
PKG_LICENSE="Apache 2.0"
PKG_NAME="mod-dims"
PKG_MAINTAINER="jeremy.collins@beetlebug.org"

cd build || exit

if [ ! -f "./configure" ]; then
    ./autorun.sh --with-apxs=$(command -v apxs2)
fi

make
make install

set -e

APACHE_RUN_DIR=/var/run/apache2
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_PID_FILE=$APACHE_RUN_DIR/apache2.pid
APACHE_LOCK_DIR=$APACHE_RUN_DIR
APACHE_LOG_DIR=$APACHE_RUN_DIR/logs

rm -rf $APACHE_RUN_DIR
mkdir -p $APACHE_RUN_DIR/logs
chown $APACHE_RUN_USER:$APACHE_RUN_GROUP $APACHE_RUN_DIR/logs

exec env APACHE_RUN_DIR=$APACHE_RUN_DIR \
    APACHE_RUN_USER=$APACHE_RUN_USER \
    APACHE_RUN_GROUP=$APACHE_RUN_GROUP \
    APACHE_PID_FILE=$APACHE_PID_FILE \
    APACHE_LOCK_DIR=$APACHE_LOCK_DIR \
    APACHE_LOG_DIR=$APACHE_LOG_DIR \
    apache2 -DFOREGROUND "$@"
