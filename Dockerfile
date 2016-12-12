FROM httpd:2.2

RUN buildDeps=' \
    		autotools-dev \
    		automake \
    		libtool \
    		make \
    	' && \
    	set -x -v && \
        apt-get update && \
        apt-get -y --no-install-recommends install $buildDeps libmagickcore-dev libmagickwand-dev  libcurl4-gnutls-dev

ADD . /var/tmp/build
RUN  cd /var/tmp/build && \
        ./autorun.sh && \
        export LDFLAGS="$LDFLAGS -L/usr/lib64/httpd" && \
        export CFLAGS="$CFLAGS -I/usr/include/httpd -I/usr/include/ImageMagick" && \
        ./configure && \
        make && \
        install -m 0644 src/.libs/libmod_dims.so -D $HTTPD_PREFIX/modules/mod_dims.so && \
        apt-get purge -y --auto-remove $buildDeps && \
        cd / && rm -rf /var/tmp/build

ADD policy.xml /etc/ImageMagick/policy.xml
