/*
 * Cache-Control, Edge-Control, Expires, ETag, and Last-Modified.
 *
 * DimsAddClient in test/conf/dims-test.conf sets trust with a source window
 * of 300 to 86400 and a client default of 604800.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

/* grid.png carries max-age=3600, which is inside the trust window. */
static void
test_trusted_source_max_age(void)
{
    dims_response *response = dims_request_ops("resize/100x100", "grid.png");

    CHECK_INT(response->status, 200, "the request");
    CHECK_STR(dims_header_value(response, "Cache-Control"), "max-age=3600, public",
              "Cache-Control");
    CHECK_STR(dims_header_value(response, "Edge-Control"), "downstream-ttl=3600",
              "Edge-Control");

    dims_response_free(response);
}

/* The pexels fixture carries max-age=99999999, above the 86400 maximum, so
 * the client default applies instead. */
static void
test_source_max_age_above_the_window(void)
{
    dims_response *response = dims_request_ops("resize/100x100",
                                               "pexels-photo-1539116.jpeg");

    CHECK_INT(response->status, 200, "the request");
    CHECK_STR(dims_header_value(response, "Cache-Control"), "max-age=604800, public",
              "Cache-Control");

    dims_response_free(response);
}

static void
test_expires_is_sent(void)
{
    dims_response *response = dims_request_ops("resize/100x100", "grid.png");

    CHECK(dims_header_value(response, "Expires") != NULL, "Expires must be sent");

    dims_response_free(response);
}

static void
test_last_modified_is_forwarded(void)
{
    dims_response *response = dims_request_ops("resize/100x100", "grid.png");
    const char *value = dims_header_value(response, "Last-Modified");

    CHECK(value != NULL, "Last-Modified must be forwarded");
    CHECK(strstr(value, "Wed, 21 Oct 2015 07:28:00 GMT") != NULL,
          "Last-Modified: want the origin value, got \"%s\"", value);

    dims_response_free(response);
}

/*
 * Finding M3. dims_write_header_cb never skips the space after the colon, so
 * every forwarded value keeps a leading space. PR 11 fixes it.
 */
static void
test_forwarded_header_has_no_leading_space(void)
{
    dims_response *response = dims_request_ops("resize/100x100", "grid.png");
    const char *raw = dims_header_raw(response, "Last-Modified");

    CHECK(raw != NULL, "Last-Modified must be forwarded");
    dims_test_logf("raw header: [%s]", raw);
    CHECK(strstr(raw, ":  ") == NULL,
          "the forwarded value keeps the space after the colon: [%s]", raw);

    dims_response_free(response);
}
static void
test_etag_is_sent(void)
{
    dims_response *response = dims_request_ops("resize/100x100", "grid.png");

    CHECK(dims_header_value(response, "ETag") != NULL, "ETag must be sent");

    dims_response_free(response);
}

/* The ETag must not change between two identical requests, or a cache in
 * front of the service never gets a hit. */
static void
test_etag_is_stable(void)
{
    dims_response *first = dims_request_ops("resize/100x100", "grid.png");
    dims_response *second = dims_request_ops("resize/100x100", "grid.png");

    CHECK_STR(dims_header_value(second, "ETag"), dims_header_value(first, "ETag"),
              "ETag");

    dims_response_free(first);
    dims_response_free(second);
}

/*
 * Finding M7. Conditional requests are never read, so a client holding a
 * valid ETag gets a full body back. PR 27 adds the 304.
 */
static void
test_conditional_request_returns_304(void)
{
    dims_response *first = dims_request_ops("resize/100x100", "grid.png");
    const char *etag = dims_header_value(first, "ETag");
    char header[512];
    const char *headers[1];
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);
    dims_response *second;

    CHECK(etag != NULL, "the first response must carry an ETag");
    snprintf(header, sizeof(header), "If-None-Match: %s", etag);
    headers[0] = header;

    second = dims_get_with_headers(path, headers, 1);
    CHECK_INT(second->status, 304, "a request with a matching ETag");

    dims_response_free(first);
    dims_response_free(second);
    free(path);
    free(url);
}

const dims_test dims_tests_cache_headers[] = {
    { "TestTrustedSourceMaxAge", test_trusted_source_max_age, NULL },
    { "TestSourceMaxAgeAboveTheWindow", test_source_max_age_above_the_window, NULL },
    { "TestExpiresIsSent", test_expires_is_sent, NULL },
    { "TestLastModifiedIsForwarded", test_last_modified_is_forwarded, NULL },
    { "TestForwardedHeaderHasNoLeadingSpace",
      test_forwarded_header_has_no_leading_space, "M3" },
    { "TestEtagIsSent", test_etag_is_sent, NULL },
    { "TestEtagIsStable", test_etag_is_stable, NULL },
    { "TestConditionalRequestReturns304", test_conditional_request_returns_304, "M7" },
    DIMS_TEST_END
};
