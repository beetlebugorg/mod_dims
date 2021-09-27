ARG HTTPD_VERSION=2.4.49

FROM httpd:${HTTPD_VERSION} as build-mod-dims

ARG DIMS_VERSION=3.3.26
ARG IMAGEMAGICK_VERSION=6.9.12-23
ARG WEBP_VERSION=1.2.1
ARG TIFF_VERSION=4.3.0
ARG PREFIX=/usr/local/imagemagick

WORKDIR /build

RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
        automake libtool autoconf build-essential \
        git ca-certificates \
        libapr1-dev libaprutil1-dev \
        curl \
        libcurl4-openssl-dev libfreetype6-dev libopenexr-dev libxml2-dev \
        libgif-dev libjpeg62-turbo-dev libpng-dev \
        liblcms2-dev pkg-config libssl-dev libpangocairo-1.0-0 wget

# WEBP Library
RUN wget https://storage.googleapis.com/downloads.webmproject.org/releases/webp/libwebp-${WEBP_VERSION}.tar.gz && \
    tar xzvf libwebp-${WEBP_VERSION}.tar.gz && \
    cd libwebp-${WEBP_VERSION} && \
    ./configure --prefix=/usr/local/imagemagick && \
    make -j4 && make install

# TIFF Library
RUN wget http://download.osgeo.org/libtiff/tiff-${TIFF_VERSION}.tar.gz && \
    tar xzvf tiff-${TIFF_VERSION}.tar.gz && \
    cd tiff-${TIFF_VERSION} && \
    ./configure --prefix=$PREFIX --with-webp-include-dir=$PREFIX/include --with-webp-lib-dir=$PREFIX/lib && \
    make -j4 && make install

# Imagemagick
RUN wget https://download.imagemagick.org/ImageMagick/download/releases/ImageMagick-${IMAGEMAGICK_VERSION}.tar.gz && \
    export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig && \
    tar xvf ImageMagick-${IMAGEMAGICK_VERSION}.tar.gz && \
    cd ImageMagick-${IMAGEMAGICK_VERSION} && \
    ./configure --without-x --with-quantum-depth=8 --prefix=$PREFIX && \
    make -j4 && make install

RUN apt-get --no-install-recommends install -y apt-transport-https apt-utils \
            automake autoconf build-essential ccache cmake ca-certificates curl git \
            gcc g++ libc-ares-dev libc-ares2 libcurl4-openssl-dev libre2-dev \
            libssl-dev m4 make pkg-config tar wget zlib1g-dev

ENV PKG_CONFIG_PATH=/usr/local/imagemagick/pkgconfig

COPY . /build/mod_dims
WORKDIR /build/mod_dims
RUN export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig && \
    ./autorun.sh && \
    ./configure && \
    make && \
    make install

FROM httpd:${HTTPD_VERSION}

ENV DIMS_DOWNLOAD_TIMEOUT=60000
ENV DIMS_IMAGEMAGICK_TIMEOUT=20000
ENV DIMS_CLIENT=development
ENV DIMS_NO_IMAGE_URL="http://placehold.it/350x150"
ENV DIMS_DEFAULT_IMAGE_URL="http://placehold.it/350x150"
ENV DIMS_CACHE_CONTROL_MAX_AGE=604800
ENV DIMS_EDGE_CONTROL_DOWNSTREAM_TTL=604800
ENV DIMS_TRUST_SOURCE=true
ENV DIMS_MIN_SOURCE_CACHE=604800
ENV DIMS_MAX_SOURCE_CACHE=604800
ENV DIMS_SECRET=""
ENV DIMS_CACHE_EXPIRE=604800
ENV DIMS_NO_IMAGE_CACHE_EXPIRE=60
ENV LC_ALL="C"

USER root

COPY --from=build-mod-dims /usr/local/apache2/modules/libmod_dims.so /usr/local/apache2/modules/
COPY --from=build-mod-dims /usr/local/imagemagick /usr/local/imagemagick
COPY docker/dims.conf /usr/local/apache2/conf/extra/dims.conf

RUN apt-get update && \
    apt-get -y install libcurl4 \
        libpangocairo-1.0-0 libgif7 libjpeg62-turbo libpng16-16 libgomp1 libjbig0 liblcms2-2 \
        libbz2-1.0 libfftw3-double3 libfontconfig1 libfreetype6 libheif1 \
        liblqr-1-0 libltdl7 liblzma5 libopenjp2-7 libopenexr23 ca-certificates && \
    rm -rf /usr/local/apache2/build \
        /usr/local/apache2/cgi-bin \
        /usr/local/apache2/include \
        /usr/local/apache2/htdocs/index.html && \
    chown -R www-data:www-data /usr/local/apache2 && \
    sed "s|Listen 80|Listen 8000|" /usr/local/apache2/conf/httpd.conf -i && \
    sed "s|^#LoadModule authz_core_module|LoadModule authz_core_module|" /usr/local/apache2/conf/httpd.conf -i && \
    echo "Include conf/extra/dims.conf" >> /usr/local/apache2/conf/httpd.conf

USER 33