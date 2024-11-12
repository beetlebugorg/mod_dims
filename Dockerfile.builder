ARG DEBIAN_VERSION=bookworm-slim
ARG HTTPD_VERSION=2.4.62

# -- Alpine Base
FROM debian:${DEBIAN_VERSION} AS debian-base

RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
        automake libtool autoconf build-essential \
        git ca-certificates \
        libapr1-dev libaprutil1-dev \
        curl \
        libcurl4-openssl-dev libfreetype6-dev libopenexr-dev libxml2-dev \
        libgif-dev libjpeg62-turbo-dev libpng-dev \
        liblcms2-dev pkg-config libssl-dev wget

# -- Build libpng
FROM debian-base AS libpng

ARG PREFIX=/usr/local/dims/libpng
ARG PNG_VERSION=1.6.43
ARG PNG_HASH="sha256:6a5ca0652392a2d7c9db2ae5b40210843c0bbc081cbd410825ab00cc59f14a6c"

ENV PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
ENV LD_LIBRARY_PATH=${PREFIX}/lib

WORKDIR /build

ADD --checksum="${PNG_HASH}" \
    https://versaweb.dl.sourceforge.net/project/libpng/libpng16/${PNG_VERSION}/libpng-${PNG_VERSION}.tar.xz \
    libpng-${PNG_VERSION}.tar.xz

RUN tar xvf "libpng-${PNG_VERSION}.tar.xz" && \
    cd "libpng-${PNG_VERSION}" && \
    ./configure --prefix="${PREFIX}" --enable-static && \
    make -j"$(nproc)" && \
    make install

# -- Build libwebp
FROM debian-base AS libwebp

ARG PREFIX=/usr/local/dims/libwebp
ARG WEBP_VERSION=1.2.1
ARG WEBP_HASH="sha256:808b98d2f5b84e9b27fdef6c5372dac769c3bda4502febbfa5031bd3c4d7d018"

WORKDIR /build

ADD --checksum="${WEBP_HASH}" \
    https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-${WEBP_VERSION}.tar.gz \
    libwebp-${WEBP_VERSION}.tar.gz

RUN tar xzvf libwebp-${WEBP_VERSION}.tar.gz && \
    cd libwebp-${WEBP_VERSION} && \
    ./configure --prefix=${PREFIX} --enable-static && \
    make -j"$(nproc)" && \
    make install

# -- Build libtiff
FROM debian-base AS libtiff

ARG PREFIX=/usr/local/dims
ARG TIFF_VERSION=4.3.0
ARG TIFF_HASH="sha256:0e46e5acb087ce7d1ac53cf4f56a09b221537fc86dfc5daaad1c2e89e1b37ac8"

WORKDIR /build

COPY --from=libwebp ${PREFIX}/libwebp ${PREFIX}/libwebp

ADD --checksum="${TIFF_HASH}" \
    https://download.osgeo.org/libtiff/tiff-${TIFF_VERSION}.tar.gz \
    tiff-${TIFF_VERSION}.tar.gz

RUN tar xzvf tiff-${TIFF_VERSION}.tar.gz && \
    cd tiff-${TIFF_VERSION} && \
    ./configure --prefix=$PREFIX/libtiff --enable-static \
        --with-webp-include-dir=$PREFIX/libwebp/include \
        --with-webp-lib-dir=$PREFIX/libwebp/lib && \
    make -j"$(nproc)" && \
    make install

# -- Build Imagemagick
FROM debian-base AS imagemagick

ARG PREFIX=/usr/local/dims
ARG IMAGEMAGICK_VERSION=7.1.1-29
ARG IMAGEMAGICK_HASH="sha256:f140465fbeb0b4724cba4394bc6f6fb32715731c1c62572d586f4f1c8b9b0685"

WORKDIR /build

COPY --from=libwebp ${PREFIX}/libwebp ${PREFIX}/libwebp
COPY --from=libtiff ${PREFIX}/libtiff ${PREFIX}/libtiff
COPY --from=libpng  ${PREFIX}/libpng  ${PREFIX}/libpng

ENV PKG_CONFIG_PATH=${PREFIX}/libwebp/lib/pkgconfig
ENV PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX}/libtiff/lib/pkgconfig
ENV PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX}/libpng/lib/pkgconfig

ADD --checksum="${IMAGEMAGICK_HASH}" \
    https://imagemagick.org/archive/releases/ImageMagick-${IMAGEMAGICK_VERSION}.tar.xz .

RUN tar xvf ImageMagick-${IMAGEMAGICK_VERSION}.tar.xz && \
    cd ImageMagick-${IMAGEMAGICK_VERSION} && \
    ./configure --enable-opencl --with-openmp --with-magick-plus-plus=no \
    --with-modules=no --enable-hdri=no --without-utilities --disable-dpc \
    --enable-zero-configuration --with-threads --with-quantum-depth=8 \
    --disable-docs --without-openexr --without-lqr --without-x --without-jbig \
    --with-png=yes --with-jpeg=yes --with-xml=yes --with-webp=yes --with-tiff=yes \
    --prefix=${PREFIX}/imagemagick && \
    make -j"$(nproc)" && \
    make install && \
    rm -rf ${PREFIX}/imagemagick/bin && \
    rm -rf ${PREFIX}/imagemagick/etc && \
    rm -rf ${PREFIX}/imagemagick/share

# -- Build base
FROM httpd:${HTTPD_VERSION}

WORKDIR /build

ARG PREFIX=/usr/local/dims

RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libcurl4 libfreetype6 libopenexr-3-1-30 libxml2 \
        libgif7 libjpeg62-turbo wget xz-utils \
        liblcms2-2 libpangocairo-1.0-0 && \
    rm -rf /var/lib/apt/lists/* && \
    wget https://ziglang.org/download/0.13.0/zig-linux-aarch64-0.13.0.tar.xz && \
    tar xvf zig-linux-aarch64-0.13.0.tar.xz && \
    rm zig-linux-aarch64-0.13.0.tar.xz

COPY --from=libpng      ${PREFIX}/libpng      ${PREFIX}/libpng
COPY --from=libwebp     ${PREFIX}/libwebp     ${PREFIX}/libwebp
COPY --from=libtiff     ${PREFIX}/libtiff     ${PREFIX}/libtiff
COPY --from=imagemagick ${PREFIX}/imagemagick ${PREFIX}/imagemagick

ENV PATH=/build/zig-linux-aarch64-0.13.0:$PATH

ENV PKG_CONFIG_PATH=${PREFIX}/libwebp/lib/pkgconfig
ENV PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX}/libpng/lib/pkgconfig
ENV PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX}/libtiff/lib/pkgconfig
ENV PKG_CONFIG_PATH=$PKG_CONFIG_PATH:${PREFIX}/imagemagick/lib/pkgconfig

ENV LD_CONFIG_PATH=${PREFIX}/libwebp/lib
ENV LD_CONFIG_PATH=$LD_CONFIG_PATH:${PREFIX}/libpng/lib
ENV LD_CONFIG_PATH=$LD_CONFIG_PATH:${PREFIX}/libtiff/lib
ENV LD_CONFIG_PATH=$LD_CONFIG_PATH:${PREFIX}/imagemagick/lib
