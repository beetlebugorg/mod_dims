/*
 * The runner. It executes each registered case, catches a failure with
 * longjmp, and reports PASS, FAIL, XFAIL, or XPASS.
 *
 * An expected failure records a known defect. When one
 * starts passing the run fails, because the finding was either wrong or
 * already fixed.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test.h"

#include <errno.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static jmp_buf failure_point;
static int in_test;
static int updating;
static char failure_message[2048];

/* Marks a failure line the child writes, so the parent can echo it. */
#define DIMS_FAILURE_PREFIX "      "

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

/*
 * Runs one case in a child process.
 *
 * Two known defects are crashes: a source URL with no path, and an overlay URL
 * with no slash. A case that reproduces one must report itself, not take the
 * run down with it. Forking makes a signal just another outcome, so an
 * expected crash reads as xfail and an unexpected one names the case.
 *
 * Returns 0 when the run should still pass.
 */
static int
run_one(const dims_test *test, const char *filter, int *ran)
{
    pid_t child;
    int status;
    int failed;
    int signalled = 0;

    if (filter != NULL && strcmp(test->name, filter) != 0) {
        return 0;
    }

    *ran += 1;
    fflush(stdout);

    child = fork();
    if (child < 0) {
        printf("FAIL  %s\n      cannot fork: %s\n", test->name, strerror(errno));
        return 1;
    }

    if (child == 0) {
        failure_message[0] = '\0';
        in_test = 1;
        if (setjmp(failure_point) == 0) {
            test->fn();
            _exit(0);
        }
        /* The message goes to the parent through the pipe stdout already is. */
        printf("%s%s\n", DIMS_FAILURE_PREFIX, failure_message);
        fflush(stdout);
        _exit(1);
    }

    if (waitpid(child, &status, 0) < 0) {
        printf("FAIL  %s\n      cannot wait: %s\n", test->name, strerror(errno));
        return 1;
    }

    if (WIFSIGNALED(status)) {
        signalled = WTERMSIG(status);
        failed = 1;
    } else {
        failed = (WEXITSTATUS(status) != 0);
    }

    if (test->xfail == NULL) {
        if (signalled) {
            printf("FAIL  %s\n      the case died on signal %d (%s)\n", test->name,
                   signalled, strsignal(signalled));
            return 1;
        }
        if (failed) {
            printf("FAIL  %s\n", test->name);
            return 1;
        }
        printf("ok    %s\n", test->name);
        return 0;
    }

    if (signalled) {
        printf("xfail %s  (%s, signal %d)\n", test->name, test->xfail, signalled);
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
        } else if (strcmp(argv[i], "--verbose") == 0) {
            /* Handled by the caller. */
        } else if (strcmp(argv[i], "--list") == 0) {
            listing = 1;
        } else if (strncmp(argv[i], "--run=", 6) == 0) {
            filter = argv[i] + 6;
        } else {
            fprintf(stderr,
                    "usage: dims_test [--update-golden] [--run=NAME] [--list] [--verbose]\n");
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
