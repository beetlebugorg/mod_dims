# The test image. It builds mod_dims, keeps the build tree, and serves it, so
# ctest runs where the compose services are reachable.
#
# This is not the shipped image. docker/Dockerfile builds that, and PR 43
# rebuilds it as a slim multi-stage image.
#
# ImageMagick comes from Debian rather than from source. The module includes
# <wand/magick-wand.h>, which only version 6 provides, and bookworm packages
# 6.9.11. Pinning to the distro keeps the golden files reproducible and keeps
# this image quick to rebuild. PR 6 moves to version 7.
ARG HTTPD_VERSION=2.4.62

FROM httpd:${HTTPD_VERSION}

RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates pkg-config \
        libapr1-dev libaprutil1-dev \
        libcurl4-openssl-dev libssl-dev \
        libmagickwand-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build/mod_dims
COPY . /build/mod_dims

RUN cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo && \
    cmake --build build -j"$(nproc)" && \
    cp build/libmod_dims.so /usr/local/apache2/modules/libmod_dims.so && \
    ln -sf /build/mod_dims/build/test/dims_test /usr/local/bin/dims_test

# Only major.minor: the patch level does not change encoder output.
RUN dpkg-query -W -f='${Version}' libmagickwand-dev | \
      sed -E 's/^[0-9]+://; s/^([0-9]+\.[0-9]+).*/\1/' > /etc/dims-magick-version

ENV LC_ALL=C

# The watermark cache builds its directory as TMPDIR + "dims-cache/". glibc
# defines P_tmpdir as "/tmp" with no trailing slash, so with TMPDIR unset the
# module tries to create /tmpdims-cache at the filesystem root and the
# watermark command falls back to the error image. Setting TMPDIR with a
# trailing slash makes the watermark path deterministic here. PR 23 fixes the
# concatenation and adds DimsOverlayCacheDir.
ENV TMPDIR=/tmp/

# The loopback guard case needs a real image on 127.0.0.1, or a refusal cannot
# be told apart from an unreachable address.
COPY test/origin/grid.png /usr/local/apache2/htdocs/grid.png

COPY test/conf/dims-test.conf /usr/local/apache2/conf/extra/dims-test.conf
RUN sed -i 's|^Listen 80$|Listen 8000|' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's|^#LoadModule authz_core_module|LoadModule authz_core_module|' /usr/local/apache2/conf/httpd.conf && \
    echo "Include conf/extra/dims-test.conf" >> /usr/local/apache2/conf/httpd.conf

EXPOSE 8000
