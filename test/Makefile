# Convenience targets for the harness. The build itself is CMake:
#
#   cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
#   cmake --build build
#
# The HTTP cases need the compose services, so ctest runs inside the service
# container where the origin is reachable.
#
#   make test          both layers through ctest
#   make test-update   rewrite the golden files, then run again
#   make unit          the in-process cases only, no services needed
#   make test-shell    a shell inside the service container

COMPOSE := docker compose

# The dims container runs as this user, so golden files land owned by whoever
# ran the suite and the httpd worker shares an identity with the test binaries.
export DIMS_UID := $(shell id -u)
export DIMS_GID := $(shell id -g)

IN_CONTAINER := $(COMPOSE) exec -T -w /build/mod_dims dims

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down -v

test: up
	$(IN_CONTAINER) ctest --test-dir build --output-on-failure $(CTESTFLAGS)

unit: up
	$(IN_CONTAINER) ctest --test-dir build -L unit --output-on-failure

http: up
	$(IN_CONTAINER) ctest --test-dir build -L http --output-on-failure

test-update: up
	$(IN_CONTAINER) ./build/test/dims_test --update-golden $(RUN)
	$(IN_CONTAINER) ./build/test/dims_unit_test --update-golden $(RUN)
	$(MAKE) test

list: up
	$(IN_CONTAINER) ./build/test/dims_test --list
	$(IN_CONTAINER) ./build/test/dims_unit_test --list

test-shell: up
	$(COMPOSE) exec dims /bin/bash

.PHONY: up down test unit http test-update list test-shell
