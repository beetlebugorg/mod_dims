# The toolchain mod_dims builds against.
#
# It exists so CI does not rebuild ImageMagick on every run. Compiling
# ImageMagick from source takes minutes; pulling this image takes seconds.
#
# ImageMagick is built from source rather than taken from the distribution for
# one reason: quantum depth. Every packaged build is Q16, and this service runs
# Q8. Quantum depth sets how many bytes a channel takes in the pixel cache, so
# Q16 doubles the memory every in-flight request holds. It also changes every
# output byte.
#
# Build and publish it with:
#
#     make builder-local     one architecture, stays on this machine
#     make builder           both architectures, pushed to the registry
#
# The published tag carries the ImageMagick version, and test/Dockerfile names
# that exact tag. A rebuild of the toolchain is then a visible change to a
# file, not something that quietly moves every golden image.

ARG HTTPD_VERSION=2.4.62

FROM httpd:${HTTPD_VERSION}

ARG IMAGEMAGICK_VERSION=7.1.2-30
ARG IMAGEMAGICK_SHA256=3034a64f22398e15ee3dd1e6b1aa83d838cfc47df1bb246ae0eca9590e6ace72
ARG PREFIX=/usr/local/imagemagick

LABEL org.opencontainers.image.title="mod_dims builder"
LABEL org.opencontainers.image.description="httpd, APR, libcurl, and ImageMagick 7 at quantum depth 8"
LABEL org.opencontainers.image.source="https://github.com/beetlebugorg/mod_dims"

RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates pkg-config wget \
        libapr1-dev libaprutil1-dev \
        libcurl4-openssl-dev libssl-dev \
        libjpeg62-turbo-dev libpng-dev libtiff-dev libwebp-dev \
        liblcms2-dev libfreetype6-dev libxml2-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# Q8 with no HDRI. HDRI stores channels as floats and would undo the point
# of Q8.
RUN wget -q -O im.tar.gz \
      "https://github.com/ImageMagick/ImageMagick/archive/refs/tags/${IMAGEMAGICK_VERSION}.tar.gz" && \
    echo "${IMAGEMAGICK_SHA256}  im.tar.gz" | sha256sum -c - && \
    tar xf im.tar.gz && \
    cd "ImageMagick-${IMAGEMAGICK_VERSION}" && \
    ./configure \
        --prefix=${PREFIX} \
        --with-quantum-depth=8 \
        --disable-hdri \
        --without-x \
        --disable-openmp \
        --with-jpeg --with-png --with-tiff --with-webp \
        --with-lcms --with-freetype --with-xml \
        --without-magick-plus-plus && \
    make -j"$(nproc)" && make install && \
    cd .. && rm -rf "ImageMagick-${IMAGEMAGICK_VERSION}" im.tar.gz

ENV PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
ENV LD_LIBRARY_PATH=${PREFIX}/lib

# The golden files record what this toolchain produces, so the name says which
# toolchain it was. Only major.minor: the patch level does not change output.
RUN printf '%s-q8\n' \
      "$(echo "${IMAGEMAGICK_VERSION}" | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')" \
      > /etc/dims-magick-version
