# Convenience targets for the harness. The build itself is CMake:
#
#   cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
#   cmake --build build
#
# The HTTP cases need the compose services, so ctest runs inside the service
# container where the origin is reachable.
#
#   make test          run the suite
#   make test-update   rewrite the golden files, then run again
#   make ctest         the same cases through ctest, one process per case
#   make test-shell    a shell inside the service container

COMPOSE := docker compose

# The container runs as root. Writing golden files as root would leave them
# unwritable on the host, so the update target runs as the invoking user.
AS_USER := --user $(shell id -u):$(shell id -g)

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down -v

test: up
	$(COMPOSE) exec -T dims dims_test $(RUN)

test-update: up
	$(COMPOSE) exec -T $(AS_USER) dims dims_test --update-golden $(RUN)
	$(COMPOSE) exec -T dims dims_test $(RUN)

ctest: up
	$(COMPOSE) exec -T -w /build/mod_dims dims ctest --test-dir build -L http --output-on-failure

list: up
	$(COMPOSE) exec -T dims dims_test --list

test-shell: up
	$(COMPOSE) exec dims /bin/bash

.PHONY: up down test test-update ctest list test-shell
