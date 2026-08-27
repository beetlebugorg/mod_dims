/*
 * The runner. It executes each registered case, catches a failure with
 * longjmp, and reports PASS, FAIL, XFAIL, or XPASS.
 *
 * An expected failure records a finding from specs/code-review.md. When one
 * starts passing the run fails, because the finding was either wrong or
 * already fixed.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static jmp_buf failure_point;
static int in_test;
static int updating;
static char failure_message[2048];

int
dims_test_updating(void)
{
    return updating;
}

void
dims_test_logf(const char *fmt, ...)
{
    va_list args;

    fputs("      ", stdout);
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fputc('\n', stdout);
}

void
dims_test_failf(const char *file, int line, const char *fmt, ...)
{
    va_list args;
    int prefix;

    prefix = snprintf(failure_message, sizeof(failure_message), "%s:%d: ", file, line);
    if (prefix < 0 || (size_t) prefix >= sizeof(failure_message)) {
        prefix = 0;
    }

    va_start(args, fmt);
    vsnprintf(failure_message + prefix, sizeof(failure_message) - (size_t) prefix, fmt, args);
    va_end(args);

    if (in_test) {
        longjmp(failure_point, 1);
    }

    fprintf(stderr, "failure outside a test: %s\n", failure_message);
    exit(2);
}

/* Runs one case. Returns 0 when the run should continue to pass. */
static int
run_one(const dims_test *test, const char *filter, int *ran)
{
    int failed;

    if (filter != NULL && strstr(test->name, filter) == NULL) {
        return 0;
    }

    *ran += 1;
    failure_message[0] = '\0';

    in_test = 1;
    failed = setjmp(failure_point);
    if (!failed) {
        test->fn();
    }
    in_test = 0;

    if (test->xfail == NULL) {
        if (failed) {
            printf("FAIL  %s\n      %s\n", test->name, failure_message);
            return 1;
        }
        printf("ok    %s\n", test->name);
        return 0;
    }

    if (failed) {
        printf("xfail %s  (%s)\n", test->name, test->xfail);
        return 0;
    }

    printf("XPASS %s  (%s)\n"
           "      the case passed but is marked as an expected failure.\n"
           "      Either the finding is wrong or it is already fixed. Remove the marker.\n",
           test->name, test->xfail);
    return 1;
}

int
dims_test_main(const dims_test_group *groups, int argc, char **argv)
{
    const char *filter = NULL;
    int listing = 0;
    int failures = 0;
    int ran = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--update-golden") == 0) {
            updating = 1;
        } else if (strcmp(argv[i], "--list") == 0) {
            listing = 1;
        } else if (strncmp(argv[i], "--run=", 6) == 0) {
            filter = argv[i] + 6;
        } else {
            fprintf(stderr,
                    "usage: dims_test [--update-golden] [--run=SUBSTRING] [--list]\n");
            return 2;
        }
    }

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (listing) {
        const dims_test_group *group;

        for (group = groups; group->file != NULL; group++) {
            const dims_test *test;

            for (test = group->tests; test->name != NULL; test++) {
                printf("%s\t%s\t%s\n", group->file, test->name,
                       test->xfail ? test->xfail : "-");
            }
        }
        return 0;
    }

    for (; groups->file != NULL; groups++) {
        const dims_test *test;

        printf("# %s\n", groups->file);
        for (test = groups->tests; test->name != NULL; test++) {
            failures += run_one(test, filter, &ran);
        }
    }

    if (ran == 0) {
        fprintf(stderr, "no test matched\n");
        return 2;
    }

    printf("\n%d cases, %d failures\n", ran, failures);

    if (updating) {
        printf("golden files updated. Run again without --update-golden.\n");
    }

    return failures == 0 ? 0 : 1;
}
