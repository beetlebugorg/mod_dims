# Builder and runner for the mod_dims test harness.
#
# The image builds mod_dims from the working tree with the autotools build that
# master still uses. PR 2 replaces that with CMake.
#
# ImageMagick comes from Debian rather than from source. The module includes
# <wand/magick-wand.h>, which only version 6 provides, and bookworm packages
# 6.9.11. Pinning to the distro keeps the golden files reproducible and keeps
# this image quick to rebuild. PR 6 moves to version 7 and PR 8 pins the
# toolchain the shipped container uses.
ARG HTTPD_VERSION=2.4.62

FROM httpd:${HTTPD_VERSION} AS build

RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
        automake libtool autoconf build-essential ca-certificates pkg-config \
        libapr1-dev libaprutil1-dev \
        libcurl4-openssl-dev libssl-dev \
        libmagickwand-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . /build/mod_dims
WORKDIR /build/mod_dims

# The test binary. It links libcurl and libcrypto, both already module
# dependencies.
RUN make -C test dims_test

RUN ./autorun.sh && make && \
    cp src/.libs/libmod_dims.so /usr/local/apache2/modules/libmod_dims.so

# Record what the golden files were produced against.
# Only major.minor: the patch level does not change encoder output.
RUN dpkg-query -W -f='${Version}' libmagickwand-dev | \
      sed -E 's/^[0-9]+://; s/^([0-9]+\.[0-9]+).*/\1/' > /build/magick-version

FROM httpd:${HTTPD_VERSION} AS runtime

RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
        libapr1 libaprutil1 libcurl4 libmagickwand-6.q16-6 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/apache2/modules/libmod_dims.so /usr/local/apache2/modules/
COPY --from=build /build/mod_dims/test/dims_test /usr/local/bin/dims_test
COPY --from=build /build/magick-version /etc/dims-magick-version

ENV LC_ALL=C

# The loopback guard case needs a real image on 127.0.0.1, or a refusal
# cannot be told apart from an unreachable address.
COPY test/origin/grid.png /usr/local/apache2/htdocs/grid.png

COPY test/conf/dims-test.conf /usr/local/apache2/conf/extra/dims-test.conf
RUN sed -i 's|^Listen 80$|Listen 8000|' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's|^#LoadModule authz_core_module|LoadModule authz_core_module|' /usr/local/apache2/conf/httpd.conf && \
    echo "Include conf/extra/dims-test.conf" >> /usr/local/apache2/conf/httpd.conf

EXPOSE 8000
