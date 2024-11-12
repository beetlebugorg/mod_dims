ARG ALPINE_VERSION=3.20

FROM --platform=linux/arm64 ghcr.io/beetlebugorg/mod-dims:builder AS mod-dims
ARG PREFIX=/usr/local/dims
ENV TARGETARCH=aarch64

ADD https://ziglang.org/download/0.13.0/zig-linux-${TARGETARCH}-0.13.0.tar.xz .

RUN tar xf zig-linux-${TARGETARCH}-0.13.0.tar.xz
RUN apk update && apk add openssl-dev curl-dev expat-dev

COPY . /build/mod-dims
WORKDIR /build/mod-dims
RUN export PATH=$PATH:/build/mod-dims/zig-linux-${TARGETARCH}-0.13.0 && \ 
    zig build --verbose && \
    cp zig-out/lib/libmod_dims.so.4.0.0 ${PREFIX}/apache2/modules/libmod_dims.so

FROM alpine:${ALPINE_VERSION}
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
ENV PATH=${PREFIX}/apache2/bin:${PATH}

COPY --from=mod-dims /build/mod-dims/zig-out/lib/libmod_dims.so.4.0.0 /usr/local/apache2/modules/libmod_dims.so
COPY --from=mod-dims ${PREFIX}/libpng      ${PREFIX}/libpng
COPY --from=mod-dims ${PREFIX}/libwebp     ${PREFIX}/libwebp
COPY --from=mod-dims ${PREFIX}/libtiff     ${PREFIX}/libtiff
COPY --from=mod-dims ${PREFIX}/imagemagick ${PREFIX}/imagemagick
COPY --from=mod-dims ${PREFIX}/apache2     ${PREFIX}/apache2
COPY dims.conf /usr/local/dims/apache2/conf/extra/dims.conf
COPY httpd.conf /usr/local/dims/apache2/conf/httpd.conf

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}" && \
    chown -R ${USER}:${USER} ${PREFIX}/apache2/logs && \
    apk update && apk add pcre libexpat libcurl libgomp libgcc gcompat

EXPOSE 80
STOPSIGNAL SIGWINCH
USER 10001:10001
CMD ["httpd", "-DFOREGROUND"]