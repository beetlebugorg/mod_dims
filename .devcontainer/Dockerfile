ARG HTTPD_VERSION=2.4.62

FROM httpd:${HTTPD_VERSION}-alpine

ENV DIMS_DOWNLOAD_TIMEOUT=60000
ENV DIMS_IMAGEMAGICK_TIMEOUT=20000
ENV DIMS_CACHE_CONTROL_MAX_AGE=604800
ENV DIMS_EDGE_CONTROL_DOWNSTREAM_TTL=604800
ENV DIMS_TRUST_SOURCE=true
ENV DIMS_MAX_SOURCE_CACHE=604800
ENV DIMS_CACHE_EXPIRE=604800
ENV DIMS_NO_IMAGE_CACHE_EXPIRE=60
ENV PREFIX=/usr/local/apache2
ENV PATH=${PREFIX}/bin:${PATH}

COPY . /build/mod-dims
WORKDIR /build/mod-dims

RUN apk update && \
    apk add vim gdb zig apr-dev apr-util-dev imagemagick-dev curl-dev \
    imagemagick-jpeg imagemagick-webp imagemagick-tiff && \
    zig build || true; \
    ln -sf /build/mod-dims/zig-out/lib/libmod_dims.so.4.0.0 ${PREFIX}/modules/libmod_dims.so || true

COPY dims.conf /usr/local/apache2/conf/httpd.conf

ENV DIMS_CLIENT=development
ENV DIMS_NO_IMAGE_URL="http://placehold.it/350x150"
ENV DIMS_DEFAULT_IMAGE_URL="http://placehold.it/350x150"