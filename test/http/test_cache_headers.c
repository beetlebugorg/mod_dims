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

/* grid.png has max-age=3600, which is inside the trust window. */
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

/* The pexels fixture has max-age=99999999, above the 86400 maximum, so
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
 * dims_write_header_cb never skips the space after the colon, so
 * every forwarded value keeps a leading space.
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
 * Conditional requests are never read, so a client holding a
 * valid ETag gets a full body back. Answering with 304 is the fix.
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

    CHECK(etag != NULL, "the first response must have an ETag");
    snprintf(header, sizeof(header), "If-None-Match: %s", etag);
    headers[0] = header;

    second = dims_get_with_headers(path, headers, 1);
    CHECK_INT(second->status, 304, "a request with a matching ETag");

    dims_response_free(first);
    dims_response_free(second);
    free(path);
    free(url);
}

/*
 * libcurl reports every response in a redirect chain. Only the last one
 * describes the body. The hop here sends its own cache headers and the target
 * does not send any.
 */
static void
test_redirect_headers_do_not_survive(void)
{
    char *url = dims_fixture_url("redirect-cached");
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);
    dims_response *response = dims_get(path);
    const char *etag = dims_header_value(response, "ETag");
    const char *modified = dims_header_value(response, "Last-Modified");

    CHECK_INT(response->status, 200,
              "a redirect to a target that does not send them");

    dims_test_logf("ETag [%s] Last-Modified [%s]", etag ? etag : "(none)",
                   modified ? modified : "(none)");
    CHECK(etag == NULL || strstr(etag, "from-the-redirect") == NULL,
          "the hop's ETag must not describe the body: %s", etag);
    CHECK(modified == NULL || strstr(modified, "1970") == NULL,
          "the hop's Last-Modified must not describe the body: %s", modified);
    CHECK(modified == NULL,
          "a target that does not send Last-Modified must not produce one: %s",
          modified);

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * The header comes from the bytes written. A multi-frame source made it
 * disagree with the body, because one call serialized every frame and the
 * other measured the current one.
 */
static void
test_content_length_matches_a_multi_frame_body(void)
{
    dims_response *response = dims_request_ops("format/gif", "animated.gif");
    const char *header = dims_header_value(response, "Content-Length");
    dims_image_size size;

    CHECK_INT(response->status, 200, "an animated GIF");
    size = dims_must_size(response->body, response->body_len);
    dims_test_logf("%ld frames, %zu bytes, Content-Length %s", size.frames,
                   response->body_len, header ? header : "(none)");

    CHECK(header != NULL, "the response must have Content-Length");
    if (header != NULL) {
        CHECK_INT(atol(header), (long) response->body_len, "Content-Length");
    }

    dims_response_free(response);
}

const dims_test dims_tests_cache_headers[] = {
    { "TestTrustedSourceMaxAge", test_trusted_source_max_age, NULL },
    { "TestSourceMaxAgeAboveTheWindow", test_source_max_age_above_the_window, NULL },
    { "TestExpiresIsSent", test_expires_is_sent, NULL },
    { "TestLastModifiedIsForwarded", test_last_modified_is_forwarded, NULL },
    { "TestForwardedHeaderHasNoLeadingSpace",
      test_forwarded_header_has_no_leading_space, NULL },
    { "TestEtagIsSent", test_etag_is_sent, NULL },
    { "TestEtagIsStable", test_etag_is_stable, NULL },
    { "TestConditionalRequestReturns304", test_conditional_request_returns_304,
      "conditional requests are never read" },
    { "TestRedirectHeadersDoNotSurvive", test_redirect_headers_do_not_survive,
      NULL },
    { "TestContentLengthMatchesAMultiFrameBody",
      test_content_length_matches_a_multi_frame_body, NULL },
    DIMS_TEST_END
};
