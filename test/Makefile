# The test harness. PR 2 folds this into the CMake build.
#
# make test          run the suite against the compose services
# make test-update   rewrite the golden files, then run again
# make test-shell    a shell inside the service container

CC      ?= cc
CFLAGS  ?= -std=c99 -O1 -g -Wall -Wextra -Wstrict-prototypes -Wwrite-strings \
           -Wformat-security -D_GNU_SOURCE
LDLIBS  ?= $(shell pkg-config --libs libcurl libcrypto)
CFLAGS  += $(shell pkg-config --cflags libcurl libcrypto)

SOURCES := $(wildcard lib/*.c) $(wildcard http/*.c)
OBJECTS := $(SOURCES:.c=.o)

COMPOSE := docker compose

# The container runs as root. Writing golden files as root would leave them
# unwritable on the host, so the update target runs as the invoking user.
AS_USER := --user $(shell id -u):$(shell id -g)

dims_test: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJECTS) dims_test

# -- Running the suite

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down -v

test: up
	$(COMPOSE) exec -T dims dims_test $(RUN)

test-update: up
	$(COMPOSE) exec -T $(AS_USER) dims dims_test --update-golden $(RUN)
	$(COMPOSE) exec -T dims dims_test $(RUN)

test-shell: up
	$(COMPOSE) exec dims /bin/bash

.PHONY: clean up down test test-update test-shell
