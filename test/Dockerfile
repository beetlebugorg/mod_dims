# The test image. It builds mod_dims, keeps the build tree, and serves it, so
# ctest runs where the compose services are reachable.
#
# This is not the shipped image. docker/Dockerfile builds that, and it is
# rebuilt separately.
#
# ImageMagick is built from source rather than taken from the distribution,
# for one reason: quantum depth. Every packaged build is Q16, and this service
# has always run Q8. The quantum depth sets how many bytes a channel takes in
# the pixel cache, so Q16 doubles the memory every request holds. It also
# changes every output byte, so it is not a detail that can be settled later.
ARG HTTPD_VERSION=2.4.62
ARG IMAGEMAGICK_VERSION=7.1.2-30
ARG IMAGEMAGICK_SHA256=3034a64f22398e15ee3dd1e6b1aa83d838cfc47df1bb246ae0eca9590e6ace72

FROM httpd:${HTTPD_VERSION} AS build

ARG IMAGEMAGICK_VERSION
ARG IMAGEMAGICK_SHA256
ARG PREFIX=/usr/local/imagemagick

RUN apt-get -y update && \
    apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates pkg-config wget \
        libapr1-dev libaprutil1-dev \
        libcurl4-openssl-dev libssl-dev \
        libjpeg62-turbo-dev libpng-dev libtiff-dev libwebp-dev \
        liblcms2-dev libfreetype6-dev libxml2-dev zlib1g-dev && \

    rm -rf /var/lib/apt/lists/*
# Q8 with no HDRI, which is what this service runs. HDRI stores channels as
# floats and would undo the point of Q8.
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

WORKDIR /build/mod_dims
COPY . /build/mod_dims

RUN cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo && \
    cmake --build build -j"$(nproc)" && \
    cp build/libmod_dims.so /usr/local/apache2/modules/libmod_dims.so && \
    ln -sf /build/mod_dims/build/test/dims_test /usr/local/bin/dims_test && \
    ln -sf /build/mod_dims/build/test/dims_unit_test /usr/local/bin/dims_unit_test && \
    chmod -R a+rwX /build/mod_dims/build

# The golden files record what this build produces, so the name says which
# build it was. Only major.minor: the patch level does not change output.
RUN printf '%s-q8\n' \
      "$(echo "${IMAGEMAGICK_VERSION}" | sed -E 's/^([0-9]+\.[0-9]+).*/\1/')" \
      > /etc/dims-magick-version

ENV LC_ALL=C

# The watermark cache builds its directory as TMPDIR + "dims-cache/". A libc
# that defines P_tmpdir without a trailing slash makes the module try to create
# /tmpdims-cache at the filesystem root, and the watermark command then falls
# back to the error image. Setting TMPDIR with a trailing slash makes the
# watermark path deterministic here. Fixing the concatenation in the module is
# a separate change.
ENV TMPDIR=/tmp/

# The loopback guard case needs a real image on 127.0.0.1, or a refusal cannot
# be told apart from an unreachable address.
COPY test/origin/grid.png /usr/local/apache2/htdocs/grid.png

# The container runs as the invoking user. httpd cannot drop privileges when
# it did not start as root, so the User and Group directives go away, and the
# pid file moves somewhere any uid can write.
RUN sed -i -E 's@^(User|Group) @# \1 @' /usr/local/apache2/conf/httpd.conf && \
    printf 'PidFile /tmp/httpd.pid\nServerName dims\n' >> /usr/local/apache2/conf/httpd.conf

COPY test/conf/dims-test.conf /usr/local/apache2/conf/extra/dims-test.conf
RUN sed -i 's|^Listen 80$|Listen 8000|' /usr/local/apache2/conf/httpd.conf && \
    sed -i 's|^#LoadModule authz_core_module|LoadModule authz_core_module|' /usr/local/apache2/conf/httpd.conf && \
    echo "Include conf/extra/dims-test.conf" >> /usr/local/apache2/conf/httpd.conf

EXPOSE 8000
