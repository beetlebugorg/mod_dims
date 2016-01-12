FROM httpd:2.2

ADD . /var/tmp/build

RUN buildDeps=' \
    		autotools-dev \
    		automake \
    		libtool \
    		make \
    	' && \
    	set -x -v && \
    	cd /var/tmp/build && \
        apt-get update && \
        apt-get -y --no-install-recommends install $buildDeps libmagickcore-dev libmagickwand-dev  libcurl4-gnutls-dev && \
        ./autorun.sh && \
        export LDFLAGS="$LDFLAGS -L/usr/lib64/httpd" && \
        export CFLAGS="$CFLAGS -I/usr/include/httpd -I/usr/include/ImageMagick" && \
        ./configure && \
        make && \
        install -m 0644 src/.libs/libmod_dims.so -D $HTTPD_PREFIX/modules/mod_dims.so && \
        apt-get purge -y --auto-remove $buildDeps && \
        cd / && rm -rf /var/tmp/build

