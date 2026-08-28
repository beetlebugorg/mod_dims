# Convenience targets for the harness. The build itself is CMake:
#
#   cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
#   cmake --build build
#
# The HTTP cases need the compose services, so ctest runs inside the service
# container where the origin is reachable. CI calls these same targets, so a
# green run here and a green run there mean the same thing.
#
#   make build         build the image only
#   make test          every case through ctest
#   make unit          the in-process cases only
#   make http          the request cases only
#   make test-update   rewrite the golden files, then run everything
#   make sanitize      the in-process cases under the sanitizers
#   make test-shell    a shell inside the service container

COMPOSE := docker compose

# The dims container runs as this user, so golden files land owned by whoever
# ran the suite and the httpd worker shares an identity with the test binaries.
export DIMS_UID := $(shell id -u)
export DIMS_GID := $(shell id -g)

IN_CONTAINER := $(COMPOSE) exec -T -w /build/mod_dims dims

build:
	$(MAKE) -C .. toolchain
	$(COMPOSE) build dims

up: build
	$(COMPOSE) up -d

down:
	$(COMPOSE) down -v

test: up
	$(IN_CONTAINER) ctest --test-dir build --output-on-failure $(CTESTFLAGS)

unit: up
	$(IN_CONTAINER) ctest --test-dir build -L unit --output-on-failure $(CTESTFLAGS)

http: up
	$(IN_CONTAINER) ctest --test-dir build -L http --output-on-failure $(CTESTFLAGS)

test-update: up
	$(IN_CONTAINER) ./build/test/dims_test --update-golden $(RUN)
	$(IN_CONTAINER) ./build/test/dims_unit_test --update-golden $(RUN)
	$(MAKE) test

# Reads of uninitialized or out of bounds memory produce a wrong answer only
# sometimes, so a normal run cannot see them. Leak detection runs here too:
# each case leaves through _exit, and lib/test.c asks for the check first.
sanitize: up
	$(IN_CONTAINER) sh -c 'cmake -B /tmp/build-asan -S /build/mod_dims \
	    -DCMAKE_BUILD_TYPE=Debug -DDIMS_SANITIZE=address,undefined >/dev/null \
	    && cmake --build /tmp/build-asan --target dims_unit_test -j"$$(nproc)"'
	$(IN_CONTAINER) sh -c 'ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 \
	    /tmp/build-asan/test/dims_unit_test'

logs:
	$(COMPOSE) logs dims

list: up
	$(IN_CONTAINER) ./build/test/dims_test --list
	$(IN_CONTAINER) ./build/test/dims_unit_test --list

test-shell: up
	$(COMPOSE) exec dims /bin/bash

.PHONY: build up down test unit http test-update sanitize logs list test-shell
