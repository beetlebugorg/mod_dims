# The mod_dims server image.
#
# Two stages. The first builds the module against the toolchain image, which
# already has httpd, APR, libcurl, and ImageMagick at quantum depth 8. The
# second is a clean httpd with the module and the ImageMagick runtime copied
# in.
#
#     docker build -f docker/Dockerfile -t mod_dims .
#     docker run -p 8000:8000 mod_dims
#
# It starts with no environment set. Every DIMS_ variable below has a default.

ARG BUILDER_IMAGE=ghcr.io/beetlebugorg/mod_dims:builder-im7.1.2-30-r3
ARG HTTPD_VERSION=2.4.68
ARG HTTPD_DIGEST=sha256:979c38c2228d28c2edfd45c6e27dcee1c7b4a101a5526721ae8ece454e89e99e

FROM ${BUILDER_IMAGE} AS build

# The build context excludes .git, so the commit comes in as an argument.
# Without it the status page reports "unknown".
ARG DIMS_COMMIT=unknown

WORKDIR /build/mod_dims
COPY . /build/mod_dims

RUN cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DDIMS_COMMIT="${DIMS_COMMIT}" && \
    cmake --build build -j"$(nproc)"

FROM httpd:${HTTPD_VERSION}@${HTTPD_DIGEST}

LABEL org.opencontainers.image.title="mod_dims"
LABEL org.opencontainers.image.description="An Apache httpd module that resizes, crops, and reformats images on request"
LABEL org.opencontainers.image.source="https://github.com/beetlebugorg/mod_dims"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Every one has a default, so the container starts with no environment set.
ENV DIMS_DOWNLOAD_TIMEOUT=60000
ENV DIMS_IMAGEMAGICK_TIMEOUT=20000
ENV DIMS_CLIENT=development
ENV DIMS_NO_IMAGE_URL="-"
ENV DIMS_DEFAULT_IMAGE_URL="-"
ENV DIMS_CACHE_CONTROL_MAX_AGE=604800
ENV DIMS_EDGE_CONTROL_DOWNSTREAM_TTL=604800
ENV DIMS_TRUST_SOURCE=trust
ENV DIMS_MIN_SOURCE_CACHE=604800
ENV DIMS_MAX_SOURCE_CACHE=604800
ENV DIMS_SECRET="-"
ENV DIMS_WHITELIST=""
ENV DIMS_CACHE_EXPIRE=604800
ENV DIMS_NO_IMAGE_CACHE_EXPIRE=60
ENV LC_ALL="C"

# The image libraries are not installed here. The builder compiles each one
# from source into /usr/local/imagemagick, and that whole prefix is copied
# below, so the version ImageMagick was compiled against is the version it
# loads.
#
# curl is for the health check. ca-certificates is for fetching an https
# source.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /build/mod_dims/build/libmod_dims.so /usr/local/apache2/modules/
COPY --from=build /usr/local/imagemagick /usr/local/imagemagick
COPY profiles/ /usr/local/share/mod_dims/profiles/
COPY docker/dims.conf /usr/local/apache2/conf/extra/dims.conf

ENV LD_LIBRARY_PATH=/usr/local/imagemagick/lib

# root owns the installation and the runtime user writes nothing in it. A
# process an attacker controls must not be able to rewrite its own module and
# wait for a restart.
RUN rm -rf /usr/local/apache2/build \
        /usr/local/apache2/cgi-bin \
        /usr/local/apache2/include \
        /usr/local/apache2/htdocs/index.html && \
    sed -i "s|Listen 80|Listen 8000|" /usr/local/apache2/conf/httpd.conf && \
    sed -i "s|^#LoadModule authz_core_module|LoadModule authz_core_module|" \
        /usr/local/apache2/conf/httpd.conf && \
    echo "Include conf/extra/dims.conf" >> /usr/local/apache2/conf/httpd.conf && \
    chown -R root:root /usr/local/apache2 /usr/local/imagemagick && \
    chmod -R go-w /usr/local/apache2 /usr/local/imagemagick

EXPOSE 8000
USER 33

# A real request, not a configuration check. The status handler answers
# without reaching an origin.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS -o /dev/null http://127.0.0.1:8000/dims-status/ || exit 1
