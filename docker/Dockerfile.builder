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

# Bump this when any pinned version below changes. The tag names the
# ImageMagick version and this number, so two toolchains cannot share a name.
ARG BUILDER_REVISION=2

ARG IMAGEMAGICK_VERSION=7.1.2-30
ARG IMAGEMAGICK_SHA256=3034a64f22398e15ee3dd1e6b1aa83d838cfc47df1bb246ae0eca9590e6ace72
ARG PREFIX=/usr/local/imagemagick

LABEL org.opencontainers.image.title="mod_dims builder"
LABEL org.opencontainers.image.description="httpd, APR, libcurl, and ImageMagick 7 at quantum depth 8"
LABEL org.opencontainers.image.source="https://github.com/beetlebugorg/mod_dims"

# The delegates are the encoders. Their versions decide the bytes in every
# golden file, so each one is built from source at a pinned version with a
# checksum, into the same prefix as ImageMagick.
#
# Building them rather than taking the distribution's packages does two
# things. The version that ImageMagick compiles against is the version it
# loads, because the runtime image copies this one prefix. And a bump is a
# line in this file with a diff beside it, rather than whatever the archive
# holds on the day of a rebuild.
ARG ZLIB_VERSION=1.3.1
ARG ZLIB_SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
ARG JPEG_VERSION=3.1.1
ARG JPEG_SHA256=aadc97ea91f6ef078b0ae3a62bba69e008d9a7db19b34e4ac973b19b71b4217c
ARG PNG_VERSION=1.6.50
ARG PNG_SHA256=4df396518620a7aa3651443e87d1b2862e4e88cad135a8b93423e01706232307
ARG WEBP_VERSION=1.6.0
ARG WEBP_SHA256=e4ab7009bf0629fd11982d4c2aa83964cf244cffba7347ecd39019a9e38c4564
ARG TIFF_VERSION=4.7.0
ARG TIFF_SHA256=67160e3457365ab96c5b3286a0903aa6e78bdc44c4bc737d2e486bcecb6ba976
ARG LCMS_VERSION=2.17
ARG LCMS_SHA256=d11af569e42a1baa1650d20ad61d12e41af4fead4aa7964a01f93b08b53ab074
ARG FREETYPE_VERSION=2.13.3
ARG FREETYPE_SHA256=0550350666d427c74daeb85d5ac7bb353acba5f76956395995311a9c6f063289
ARG XML2_VERSION=2.13.8
ARG XML2_SHA256=277294cb33119ab71b2bc81f2f445e9bc9435b893ad15bb2cd2b0e859a0ee84a

# Only what compiles the delegates. Every image library comes from source
# below, so none of them is installed here.
RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
        build-essential cmake nasm ca-certificates pkg-config wget xz-utils \
        libapr1-dev libaprutil1-dev \
        libcurl4-openssl-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Every delegate installs into one prefix, and each one after the first
# compiles against the ones before it.
ENV PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
ENV LD_LIBRARY_PATH=${PREFIX}/lib
ENV CPPFLAGS="-I${PREFIX}/include"
ENV LDFLAGS="-L${PREFIX}/lib -Wl,-rpath,${PREFIX}/lib"

RUN mkdir -p ${PREFIX}/include ${PREFIX}/lib

# Downloads, checks, and unpacks one release. A wrong checksum stops the
# build here rather than producing an image nobody can reproduce.
COPY docker/fetch.sh /usr/local/bin/fetch
RUN chmod +x /usr/local/bin/fetch

# zlib. libpng, libtiff, freetype, and libxml2 all want it.
RUN fetch "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz" \
        "${ZLIB_SHA256}" && \
    cd "zlib-${ZLIB_VERSION}" && \
    ./configure --prefix=${PREFIX} && \
    make -j"$(nproc)" && make install && cd .. && rm -rf "zlib-${ZLIB_VERSION}"

# libjpeg-turbo. nasm is what makes it fast.
RUN fetch "https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/${JPEG_VERSION}/libjpeg-turbo-${JPEG_VERSION}.tar.gz" \
        "${JPEG_SHA256}" && \
    cmake -S "libjpeg-turbo-${JPEG_VERSION}" -B jpeg-build \
        -DCMAKE_INSTALL_PREFIX=${PREFIX} \
        -DCMAKE_INSTALL_LIBDIR=${PREFIX}/lib \
        -DCMAKE_BUILD_TYPE=Release -DWITH_JPEG8=1 && \
    cmake --build jpeg-build -j"$(nproc)" && cmake --install jpeg-build && \
    rm -rf jpeg-build "libjpeg-turbo-${JPEG_VERSION}"

RUN fetch "https://download.sourceforge.net/libpng/libpng16/${PNG_VERSION}/libpng-${PNG_VERSION}.tar.xz" \
        "${PNG_SHA256}" && \
    cd "libpng-${PNG_VERSION}" && \
    ./configure --prefix=${PREFIX} && \
    make -j"$(nproc)" && make install && cd .. && rm -rf "libpng-${PNG_VERSION}"

RUN fetch "https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-${WEBP_VERSION}.tar.gz" \
        "${WEBP_SHA256}" && \
    cd "libwebp-${WEBP_VERSION}" && \
    ./configure --prefix=${PREFIX} --enable-libwebpmux --enable-libwebpdemux && \
    make -j"$(nproc)" && make install && cd .. && rm -rf "libwebp-${WEBP_VERSION}"

RUN fetch "https://download.osgeo.org/libtiff/tiff-${TIFF_VERSION}.tar.gz" \
        "${TIFF_SHA256}" && \
    cd "tiff-${TIFF_VERSION}" && \
    ./configure --prefix=${PREFIX} --disable-static && \
    make -j"$(nproc)" && make install && cd .. && rm -rf "tiff-${TIFF_VERSION}"

RUN fetch "https://github.com/mm2/Little-CMS/releases/download/lcms${LCMS_VERSION}/lcms2-${LCMS_VERSION}.tar.gz" \
        "${LCMS_SHA256}" && \
    cd "lcms2-${LCMS_VERSION}" && \
    ./configure --prefix=${PREFIX} && \
    make -j"$(nproc)" && make install && cd .. && rm -rf "lcms2-${LCMS_VERSION}"

RUN fetch "https://downloads.sourceforge.net/project/freetype/freetype2/${FREETYPE_VERSION}/freetype-${FREETYPE_VERSION}.tar.xz" \
        "${FREETYPE_SHA256}" && \
    cd "freetype-${FREETYPE_VERSION}" && \
    ./configure --prefix=${PREFIX} --enable-freetype-config && \
    make -j"$(nproc)" && make install && cd .. && rm -rf "freetype-${FREETYPE_VERSION}"

# libxml2 is what reads an SVG. Python and the rest of its optional parts stay
# off, because ImageMagick reads none of them.
RUN fetch "https://download.gnome.org/sources/libxml2/2.13/libxml2-${XML2_VERSION}.tar.xz" \
        "${XML2_SHA256}" && \
    cd "libxml2-${XML2_VERSION}" && \
    ./configure --prefix=${PREFIX} --without-python --without-lzma --with-zlib=${PREFIX} && \
    make -j"$(nproc)" && make install && cd .. && rm -rf "libxml2-${XML2_VERSION}"

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

# The golden files record what this toolchain produces, so the name says which
# toolchain it was. Only major.minor: the patch level does not change output.
RUN printf '%s-q8\n' \
      "$(echo "${IMAGEMAGICK_VERSION}" | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')" \
      > /etc/dims-magick-version
