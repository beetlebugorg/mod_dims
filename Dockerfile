ARG HTTPD_VERSION=2.4.62

FROM httpd:${HTTPD_VERSION}-alpine AS builder

ENV PREFIX=/usr/local/apache2
ENV PATH=${PREFIX}/bin:${PATH}

COPY . /build/mod-dims
WORKDIR /build/mod-dims

RUN apk update && \
    apk add vim gdb zig apr-dev apr-util-dev imagemagick-dev curl-dev \
    imagemagick-jpeg imagemagick-webp imagemagick-tiff && \
    zig build || true; \
    ln -sf /build/mod-dims/zig-out/lib/libmod_dims.so.4.0.0 ${PREFIX}/modules/libmod_dims.so || true

FROM httpd:${HTTPD_VERSION}-alpine AS final

ENV DIMS_DOWNLOAD_TIMEOUT=60000
ENV DIMS_IMAGEMAGICK_TIMEOUT=20000
ENV DIMS_CACHE_CONTROL_MAX_AGE=604800
ENV DIMS_EDGE_CONTROL_DOWNSTREAM_TTL=604800
ENV DIMS_TRUST_SOURCE=true
ENV DIMS_MIN_SOURCE_CACHE=0
ENV DIMS_MAX_SOURCE_CACHE=604800
ENV DIMS_CACHE_EXPIRE=604800
ENV DIMS_NO_IMAGE_CACHE_EXPIRE=60
ENV PREFIX=/usr/local/apache2
ENV PATH=${PREFIX}/bin:${PATH}

# Imagemagick configuration

# 2GB disk limit
ENV MAGICK_DISK_LIMIT=2147483648

# 512MB memory limit
ENV MAGICK_MEMORY_LIMIT=536870912

# 512MB map limit
ENV MAGICK_MAP_LIMIT=536870912

# 128MB area limit
ENV MAGICK_AREA_LIMIT=134217728

RUN apk update && \
    apk add imagemagick imagemagick-jpeg imagemagick-webp imagemagick-tiff curl 

COPY --from=builder /build/mod-dims/zig-out/lib/libmod_dims.so.4.0.0 ${PREFIX}/modules/libmod_dims.so
COPY dims.conf /usr/local/apache2/conf/httpd.conf

EXPOSE 8000