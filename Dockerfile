ARG HTTPD_VERSION=2.4.62

FROM ghcr.io/beetlebugorg/mod-dims:builder AS mod-dims

RUN apt-get update && \
    apt-get -y install \
        libpangocairo-1.0-0 libgif7 libjpeg62-turbo libpng16-16 libgomp1 libjbig0 liblcms2-2 \
        libbz2-1.0 libfftw3-double3 libfontconfig1 libfreetype6 libheif1 \
        liblqr-1-0 libltdl7 liblzma5 libopenjp2-7 libopenexr-3-1-30 ca-certificates pkg-config  \
        libapr1-dev libaprutil1-dev libcurl4-openssl-dev libssl-dev

COPY . /build/mod-dims
WORKDIR /build/mod-dims

RUN zig build

FROM httpd:${HTTPD_VERSION}
ARG PREFIX=/usr/local/dims

ENV USER=dims
ENV UID=10001
ENV DIMS_DOWNLOAD_TIMEOUT=60000
ENV DIMS_IMAGEMAGICK_TIMEOUT=20000
ENV DIMS_CLIENT=development
ENV DIMS_NO_IMAGE_URL="http://placehold.it/350x150"
ENV DIMS_DEFAULT_IMAGE_URL="http://placehold.it/350x150"
ENV DIMS_CACHE_CONTROL_MAX_AGE=604800
ENV DIMS_EDGE_CONTROL_DOWNSTREAM_TTL=604800
ENV DIMS_TRUST_SOURCE=true
ENV DIMS_SOURCE_CACHE=604800
ENV DIMS_MIN_SOURCE_CACHE=0
ENV DIMS_MAX_SOURCE_CACHE=604800
ENV DIMS_CACHE_EXPIRE=604800
ENV DIMS_NO_IMAGE_CACHE_EXPIRE=60
ENV DIMS_WHITELIST=""

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

COPY --from=mod-dims /build/mod-dims/zig-out/lib/libmod_dims.so.4.0.0 /usr/local/apache2/modules/libmod_dims.so
COPY --from=mod-dims ${PREFIX}/libpng      ${PREFIX}/libpng
COPY --from=mod-dims ${PREFIX}/libwebp     ${PREFIX}/libwebp
COPY --from=mod-dims ${PREFIX}/libtiff     ${PREFIX}/libtiff
COPY --from=mod-dims ${PREFIX}/imagemagick ${PREFIX}/imagemagick
COPY dims.conf /usr/local/apache2/conf/extra/dims.conf

RUN apt-get update && \
    apt-get -y install \
        libgif7 libjpeg62-turbo libpng16-16 libgomp1 libjbig0 liblcms2-2 \
        libbz2-1.0 libfftw3-double3 libfontconfig1 libfreetype6 libheif1 libjpeg62-turbo \
        liblqr-1-0 libltdl7 liblzma5 libopenjp2-7 libopenexr-3-1-30 ca-certificates && \
    rm -rf /usr/local/apache2/build \
        /usr/local/apache2/cgi-bin \
        /usr/local/apache2/include \
        /usr/local/apache2/htdocs/index.html && \
        find /usr/local/dims | grep \.a$ | xargs rm && \
    chown -R www-data:www-data /usr/local/apache2 && \
    sed "s|Listen 80|Listen 8000|" /usr/local/apache2/conf/httpd.conf -i && \
    sed "s|^#LoadModule authz_core_module|LoadModule authz_core_module|" /usr/local/apache2/conf/httpd.conf -i && \
    sed "s|^LogLevel warn|LogLevel debug|" /usr/local/apache2/conf/httpd.conf -i && \
    echo "Include conf/extra/dims.conf" >> /usr/local/apache2/conf/httpd.conf

EXPOSE 8080
#USER 10001:10001