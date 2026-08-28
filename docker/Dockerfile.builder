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

# The base is pinned by digest, not by tag. The tag on this image names the
# ImageMagick version, and the golden files trust that name to mean one
# toolchain. A moving base would let a rebuild publish different encoders
# under the same name, and every baseline would shift with nothing in the
# diff to show why.
ARG HTTPD_VERSION=2.4.62
ARG HTTPD_DIGEST=sha256:4c7788695c832bf415a662dfb5160f1895e65fc65c025e85f436ee2c9e7d7f3e

FROM httpd:${HTTPD_VERSION}@${HTTPD_DIGEST}

ARG IMAGEMAGICK_VERSION=7.1.2-30
ARG IMAGEMAGICK_SHA256=3034a64f22398e15ee3dd1e6b1aa83d838cfc47df1bb246ae0eca9590e6ace72
ARG PREFIX=/usr/local/imagemagick

LABEL org.opencontainers.image.title="mod_dims builder"
LABEL org.opencontainers.image.description="httpd, APR, libcurl, and ImageMagick 7 at quantum depth 8"
LABEL org.opencontainers.image.source="https://github.com/beetlebugorg/mod_dims"

# The delegates are the encoders. Their versions decide the bytes in every
# golden file, so they are pinned.
#
# Debian drops a version from the archive when a security update replaces it,
# so this build fails when that happens. That is the point: a loud failure that
# says "bump these and review the golden diff" beats a quiet rebuild that
# changes every baseline.
#
# libwebp 1.2.4-0.2+deb12u1 carries the fix for CVE-2023-4863, the heap
# overflow reachable from a crafted lossless image.
RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates pkg-config wget \
        libapr1-dev libaprutil1-dev \
        libcurl4-openssl-dev libssl-dev \
        libjpeg62-turbo-dev=1:2.1.5-2 \
        libpng-dev=1.6.39-2+deb12u5 \
        libtiff-dev=4.5.0-6+deb12u4 \
        libwebp-dev=1.2.4-0.2+deb12u1 \
        liblcms2-dev=2.14-2+deb12u1 \
        libfreetype6-dev=2.12.1+dfsg-5+deb12u4 \
        libxml2-dev=2.9.14+dfsg-1.3~deb12u6 \
        zlib1g-dev=1:1.2.13.dfsg-1 && \
    rm -rf /var/lib/apt/lists/*
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
