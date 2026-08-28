/*
 * DimsMaxSourceBytes.
 *
 * The limit defaults to no limit, so the main test server cannot exercise it.
 * The server on port 8002 sets it to one megabyte.
 *
 * The origin serves /huge.png as 64 MB with no Content-Length, so the limit
 * has to be enforced while reading rather than from a declared size.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

static const char *
limited_url(void)
{
    const char *from_env = getenv("DIMS_TEST_SIZE_LIMITED_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8002";
}

static dims_response *
limited_request(const char *fixture)
{
    char *url = dims_fixture_url(fixture);
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);
    char full[2048];
    dims_response *response;

    snprintf(full, sizeof(full), "%s%s", limited_url(), path);
    response = dims_get_absolute(full);

    free(path);
    free(url);
    return response;
}

static void
test_source_over_the_limit_is_refused(void)
{
    dims_response *response = limited_request("huge.png");

    CHECK(response->transport_error == NULL, "the worker must answer: %s",
          response->transport_error ? response->transport_error : "");
    dims_test_logf("a 64 MB source against a 1 MB limit returns %ld",
                   response->status);
    CHECK(response->status >= 400,
          "a source over the limit must be refused, got %ld", response->status);

    dims_response_free(response);
}

/* The limit must not refuse an ordinary image. */
static void
test_source_under_the_limit_is_served(void)
{
    dims_response *response = limited_request("grid.png");
    dims_image_size size;

    CHECK_INT(response->status, 200, "a source well under the limit");
    size = dims_must_size(response->body, response->body_len);
    CHECK_INT(size.width, 100, "width");

    dims_response_free(response);
}

/*
 * The same oversized source on a server with no limit. This is what the
 * default does, and what every existing deployment keeps doing.
 */
static void
test_no_limit_accepts_the_same_source(void)
{
    dims_response *response = dims_request_ops("resize/100x100", "huge.png");

    dims_test_logf("with no limit the same source returns %ld", response->status);
    CHECK(response->transport_error == NULL, "the worker must answer: %s",
          response->transport_error ? response->transport_error : "");

    dims_response_free(response);
}

const dims_test dims_tests_source_limit[] = {
    { "TestSourceOverTheLimitIsRefused", test_source_over_the_limit_is_refused, NULL },
    { "TestSourceUnderTheLimitIsServed", test_source_under_the_limit_is_served, NULL },
    { "TestNoLimitAcceptsTheSameSource", test_no_limit_accepts_the_same_source, NULL },
    DIMS_TEST_END
};
