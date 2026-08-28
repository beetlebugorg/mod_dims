/*
 * Reading a source URL out of a request path.
 *
 * The module searched for "http:/" alone, and "https:/" does not contain it,
 * so a TLS source in the path was never found.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "url.h"
#include "../lib/test.h"

#include <apr_general.h>
#include <string.h>

/* One pool for the file. apr_initialize already ran in dims_fixture_init. */
static apr_pool_t *
url_pool(void)
{
    static apr_pool_t *pool;

    if (pool == NULL && apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        FAIL("cannot create a pool");
    }

    return pool;
}

static void
check_url(const char *path, const char *want)
{
    apr_pool_t *pool = url_pool();
    char *subject = apr_pstrdup(pool, path);
    char *got = dims_path_image_url(pool, subject, NULL);

    if (want == NULL) {
        CHECK(got == NULL, "%s must have no URL, got %s", path,
              got ? got : "(null)");
        return;
    }

    CHECK(got != NULL, "%s must have a URL", path);
    if (got != NULL) {
        CHECK(strcmp(got, want) == 0, "%s: want %s, got %s", path, want, got);
    }
}

/* httpd collapses the double slash, so the URL arrives with one. */
static void
test_http_url_in_path(void)
{
    check_url("/dims3/TEST/resize/100x100/http:/example.com/a.jpg",
              "http://example.com/a.jpg");
}

/* The case the module could not read at all. */
static void
test_https_url_in_path(void)
{
    check_url("/dims3/TEST/resize/100x100/https:/example.com/a.jpg",
              "https://example.com/a.jpg");
}

/* A caller that escaped the pair needs no repair. */
static void
test_url_with_both_slashes(void)
{
    check_url("/dims3/TEST/resize/100x100/http://example.com/a.jpg",
              "http://example.com/a.jpg");
    check_url("/dims3/TEST/resize/100x100/https://example.com/a.jpg",
              "https://example.com/a.jpg");
}

static void
test_path_without_a_url(void)
{
    check_url("/dims3/TEST/resize/100x100/", NULL);
    check_url("/dims3/TEST/resize/100x100/ftp:/example.com/a.jpg", NULL);
    check_url("", NULL);
    CHECK(dims_path_image_url(url_pool(), NULL, NULL) == NULL, "no subject");
}

/*
 * The caller truncates at *start to leave the commands behind. The returned
 * URL must not point into that same memory, or the truncation would cut the
 * URL in half.
 */
static void
test_start_marks_where_the_url_begins(void)
{
    apr_pool_t *pool = url_pool();
    char *subject = apr_pstrdup(pool,
            "/dims3/TEST/resize/100x100/https:/example.com/a.jpg");
    char *start = NULL;
    char *url = dims_path_image_url(pool, subject, &start);

    CHECK(url != NULL && start != NULL, "the URL and its position");
    if (url == NULL || start == NULL) {
        return;
    }

    CHECK(strcmp(start, "https:/example.com/a.jpg") == 0,
          "start points at the URL, got %s", start);

    *start = '\0';
    CHECK(strcmp(subject, "/dims3/TEST/resize/100x100/") == 0,
          "the commands survive the truncation, got %s", subject);
    CHECK(strcmp(url, "https://example.com/a.jpg") == 0,
          "the URL survives the truncation, got %s", url);
}

/*
 * Whichever scheme appears first wins. Searching for one and then the other
 * would take an https later in the path over an http earlier in it.
 */
static void
test_first_scheme_wins(void)
{
    check_url("/dims3/TEST/resize/100x100/http:/example.com/http:/a.jpg",
              "http://example.com/http:/a.jpg");
    check_url("/dims3/TEST/resize/100x100/http:/example.com/a.jpg?u=https:/b",
              "http://example.com/a.jpg?u=https:/b");
    check_url("/dims3/TEST/resize/100x100/https:/example.com/a.jpg?u=http:/b",
              "https://example.com/a.jpg?u=http:/b");
}

const dims_test dims_tests_unit_url[] = {
    { "TestHttpUrlInPath", test_http_url_in_path, NULL },
    { "TestHttpsUrlInPath", test_https_url_in_path, NULL },
    { "TestUrlWithBothSlashes", test_url_with_both_slashes, NULL },
    { "TestPathWithoutAUrl", test_path_without_a_url, NULL },
    { "TestStartMarksWhereTheUrlBegins", test_start_marks_where_the_url_begins,
      NULL },
    { "TestFirstSchemeWins", test_first_scheme_wins, NULL },
    DIMS_TEST_END
};
