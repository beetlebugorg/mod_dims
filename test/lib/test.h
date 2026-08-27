/*
 * The test registry, the runner API, and the assertion macros.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_H
#define DIMS_TEST_H

#include <stddef.h>

typedef void (*dims_test_fn)(void);

typedef struct dims_test {
    /* The go-dims test name where the case is a port, so the two suites line
     * up. */
    const char *name;
    dims_test_fn fn;
    /* NULL when the case must pass. Otherwise a short identifier for the
     * defect the case records, so a known failure is visible without being
     * noisy. An expected failure that passes is reported as XPASS and fails
     * the run: the defect was either misdiagnosed or already fixed. */
    const char *xfail;
} dims_test;

#define DIMS_TEST_END \
    { NULL, NULL, NULL }

/* Each test_*.c exposes one of these. */
typedef struct dims_test_group {
    const char *file;
    const dims_test *tests;
} dims_test_group;

void dims_test_failf(const char *file, int line, const char *fmt, ...);
void dims_test_logf(const char *fmt, ...);

/* The runner entry point. main.c passes the group table. */
int dims_test_main(const dims_test_group *groups, int argc, char **argv);

/* True when the run was started with --update-golden. */
int dims_test_updating(void);

#define FAIL(...) dims_test_failf(__FILE__, __LINE__, __VA_ARGS__)

#define CHECK(cond, ...)             \
    do {                             \
        if (!(cond)) {               \
            FAIL(__VA_ARGS__);       \
        }                            \
    } while (0)

#define CHECK_INT(got, want, what)                                     \
    do {                                                               \
        long _g = (long) (got), _w = (long) (want);                    \
        if (_g != _w) {                                                \
            FAIL("%s: want %ld, got %ld", (what), _w, _g);             \
        }                                                              \
    } while (0)

#define CHECK_STR(got, want, what)                                     \
    do {                                                               \
        const char *_g = (got), *_w = (want);                          \
        if (_g == NULL || strcmp(_g, _w) != 0) {                       \
            FAIL("%s: want \"%s\", got \"%s\"", (what), _w,            \
                 _g ? _g : "(absent)");                                \
        }                                                              \
    } while (0)

#endif
