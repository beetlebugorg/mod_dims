# The test image. It builds mod_dims, keeps the build tree, and serves it, so
# ctest runs where the compose services are reachable.
#
# The toolchain comes from the builder image, which is where ImageMagick is
# compiled. See Dockerfile.builder.
#
# The tag names the ImageMagick version on purpose. The golden files record
# what that exact toolchain produces, so moving to a new one has to be a
# visible change to this line rather than a silent pull of a moving tag.
#
# Build the toolchain locally with `make builder-local` and point this at
# mod_dims:builder-local to try a change before publishing it.
ARG BUILDER_IMAGE=ghcr.io/beetlebugorg/mod_dims:builder-im7.1.2-30

FROM ${BUILDER_IMAGE}

WORKDIR /build/mod_dims
COPY . /build/mod_dims

RUN cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo && \
    cmake --build build -j"$(nproc)" && \
    cp build/libmod_dims.so /usr/local/apache2/modules/libmod_dims.so && \
    ln -sf /build/mod_dims/build/test/dims_test /usr/local/bin/dims_test && \
    ln -sf /build/mod_dims/build/test/dims_unit_test /usr/local/bin/dims_unit_test && \
    chmod -R a+rwX /build/mod_dims/build

ENV LC_ALL=C

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

EXPOSE 8000 8001 8002
