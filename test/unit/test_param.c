/*
 * Reading one query parameter out of a token.
 *
 * Every caller compared a prefix and then indexed the full name's length into
 * the token, so a token shorter than the name was read past its end.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "url.h"
#include "../lib/test.h"

#include <string.h>

static void
check(const char *token, const char *name, const char *want)
{
    const char *got = dims_param_value(token, name);

    if (want == NULL) {
        CHECK(got == NULL, "%s must not match %s, got %s", token, name,
              got ? got : "(null)");
        return;
    }

    CHECK(got != NULL && strcmp(got, want) == 0, "%s against %s: want %s, got %s",
          token, name, want, got ? got : "(null)");
}

static void
test_reads_the_value(void)
{
    check("url=http://example.com/a.jpg", "url=", "http://example.com/a.jpg");
    check("eurl=AAAA", "eurl=", "AAAA");
    check("overlay=x", "overlay=", "x");
    check("optimizeResize=0.5", "optimizeResize=", "0.5");
}

/* A name with no value is a match with an empty value, not a read past it. */
static void
test_reads_an_empty_value(void)
{
    check("eurl=", "eurl=", "");
    check("url=", "url=", "");
}

/*
 * The comparisons passed 4 whatever the name's length, so each of these
 * matched and the caller then read the full name's length into the token.
 * "optix=1" is seven bytes and the read started fifteen bytes in.
 */
static void
test_a_shorter_token_does_not_match(void)
{
    check("optix=1", "optimizeResize=", NULL);
    check("opti", "optimizeResize=", NULL);
    check("over", "overlay=", NULL);
    check("eurl", "eurl=", NULL);
    check("urls=x", "url=", NULL);
    check("", "url=", NULL);
}

/* A parameter with no equals sign has no value. */
static void
test_a_name_without_equals_does_not_match(void)
{
    check("download", "download=", NULL);
    check("url", "url=", NULL);
}

static void
test_no_token(void)
{
    CHECK(dims_param_value(NULL, "url=") == NULL, "no token");
    CHECK(dims_param_value("url=x", NULL) == NULL, "no name");
}

const dims_test dims_tests_unit_param[] = {
    { "TestReadsTheValue", test_reads_the_value, NULL },
    { "TestReadsAnEmptyValue", test_reads_an_empty_value, NULL },
    { "TestAShorterTokenDoesNotMatch", test_a_shorter_token_does_not_match, NULL },
    { "TestANameWithoutEqualsDoesNotMatch",
      test_a_name_without_equals_does_not_match, NULL },
    { "TestNoToken", test_no_token, NULL },
    DIMS_TEST_END
};
