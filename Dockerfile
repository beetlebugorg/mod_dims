FROM immobilienscout24/httpd_with_imagemagick_incl_webp 

ADD . /var/tmp/build

RUN buildDeps=' \
    		autotools-dev \
    		automake \
    		libtool \
    		make \
    	' && \
    	set -x -v && \
        apt-get update && \
        apt-get -y --no-install-recommends install $buildDeps && \
        apt-get install ca-certificates -y && \
        cd /var/tmp/build && \
        ./autorun.sh && \
        export LDFLAGS="$LDFLAGS -L/usr/lib64/httpd" && \
        export CFLAGS="$CFLAGS -I/usr/include/httpd -I/usr/include/ImageMagick -DAWSBUILD" && \
        ./configure && \
        make && \
        install -m 0644 src/.libs/libmod_dims.so -D $HTTPD_PREFIX/modules/mod_dims.so && \
        apt-get purge -y --auto-remove $buildDeps && \
        cd / && rm -rf /var/tmp/build && \
        sed -ri 's;set -e;set -e\n[ -d /tmp ] \&\& chmod 1777 /tmp || :;g' /usr/local/bin/httpd-foreground

ADD policy.xml /etc/ImageMagick/policy.xml
