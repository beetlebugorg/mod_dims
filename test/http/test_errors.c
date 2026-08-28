/*
 * Error paths: a bad client, a bad argument, a missing source, an origin
 * failure, and the parser cases from Stack 2.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

static void
test_unknown_client(void)
{
    dims_response *response = dims_get("/dims3/NOSUCH/resize/100x100/?url=x");

    CHECK(response->status != 200, "an unknown application id must not return 200");
    dims_test_logf("unknown client returns %ld", response->status);

    dims_response_free(response);
}

static void
test_missing_source(void)
{
    char *url = dims_fixture_url("missing.png");
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);
    dims_response *response = dims_get(path);

    CHECK_INT(response->status, 404, "a source that returns 404");

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * The origin status is copied to the client, so a 500 from the
 * origin becomes a 500 from the service. Mapping it to 502 is the fix.
 * DimsOriginStatusMode.
 */
static void
test_origin_failure_is_mapped(void)
{
    char *url = dims_fixture_url("broken.png");
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);
    dims_response *response = dims_get(path);

    dims_test_logf("an origin 500 returns %ld", response->status);
    CHECK_INT(response->status, 502, "an origin that returns 500");

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * A malformed geometry returns the fallback image with 200 today. The
 * operation fails, dims_cleanup fetches DimsDefaultImageURL, and
 * dims_send_image reports the fetch status of that image rather than the
 * failure. Each failure class needs its own status.
 */
static void
test_bad_geometry(void)
{
    dims_response *response = dims_request_ops("resize/not-a-size", "grid.png");

    dims_test_logf("a malformed geometry returns %ld with %zu bytes",
                   response->status, response->body_len);
    CHECK(response->status >= 400,
          "a malformed geometry is a client error, got %ld", response->status);

    dims_response_free(response);
}

/*
 * quality is never range checked, so 500 reaches
 * MagickSetImageCompressionQuality. The value needs a range check.
 */
static void
test_quality_out_of_range(void)
{
    dims_response *response = dims_request_ops("quality/500", "pexels-photo-1539116.jpeg");

    CHECK(response->status >= 400 && response->status < 500,
          "quality/500 is a client error, got %ld", response->status);

    dims_response_free(response);
}

/*
 * The parameter name is matched on four bytes and then indexed at
 * offset 15, which reads past the end of a short token.
 *
 * The case asserts the worker answers. Under a sanitizer build it reports the
 * read directly.
 */
static void
test_short_parameter_starting_with_opti(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4("resize/100x100", url, "optix=1", NULL);
    dims_response *response = dims_get(path);

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    CHECK_INT(response->status, 200, "a parameter the service should ignore");

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * A parameter with no equals sign makes the parser read one byte
 * past the terminator.
 */
static void
test_parameter_without_equals(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4("resize/100x100", url, "download", NULL);
    dims_response *response = dims_get(path);

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    CHECK_INT(response->status, 200, "a parameter with no value");

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * A short eurl makes the decoded length negative, and the pointer
 * arithmetic that follows runs on it. Decryption happens before any signature
 * check, so this needs no valid signature.
 */
static void
test_short_eurl(void)
{
    dims_response *response = dims_get("/dims3/" DIMS_TEST_CLIENT
                                       "/resize/100x100/?eurl=AAAA");

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    CHECK(response->status >= 400,
          "a malformed eurl is an error, got %ld", response->status);

    dims_response_free(response);
}

static void
test_empty_eurl(void)
{
    dims_response *response = dims_get("/dims3/" DIMS_TEST_CLIENT
                                       "/resize/100x100/?eurl=");

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    CHECK(response->status >= 400, "an empty eurl is an error, got %ld", response->status);

    dims_response_free(response);
}

/*
 * A parameter with no equals sign. The parser measured the token and read one
 * byte past its terminator, which for the last parameter is past the copy.
 */
static void
test_signed_parameter_without_equals(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4("resize/100x100", url, "download", NULL);
    dims_response *response = dims_get(path);

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    dims_test_logf("a signed request with a valueless parameter returns %ld",
                   response->status);
    CHECK(response->status == 200,
          "a parameter with no value must not change the signature, got %ld",
          response->status);

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * A signed request with no query string at all. _keys is absent, so the
 * tokenizer state that walks it was read before anything assigned it.
 */
static void
test_signed_request_without_a_query_string(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);
    char *question = strchr(path, '?');
    char in_path[2048];
    dims_response *response;

    /* Move the source URL from ?url= into the path, which is the form that
     * leaves the request with no query string at all. */
    CHECK(question != NULL, "the signed path has a query string");
    if (question == NULL) {
        free(path);
        free(url);
        return;
    }
    *question = '\0';

    snprintf(in_path, sizeof(in_path), "%s%s", path, url);
    response = dims_get(in_path);

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    dims_test_logf("a signed request with no query string returns %ld",
                   response->status);
    CHECK(response->status != 500,
          "a request with no query string must not fault, got %ld",
          response->status);

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * The handlers index a fixed seven bytes into the URI. A location under
 * another name satisfies the handler check with a shorter URI and left them
 * reading past its end.
 */
static void
test_endpoint_under_another_location(void)
{
    /* Three bytes. The handlers read from byte seven. */
    dims_response *response = dims_get("/i/");

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    dims_test_logf("dims4 under /i/ returns %ld", response->status);
    CHECK(response->status >= 400,
          "a location the handlers cannot read must be refused, got %ld",
          response->status);

    dims_response_free(response);
}

/*
 * DimsAddClient stores a secret of "-" as NULL. The eurl branch hashes that
 * secret with SHA1 before anything checks it, so a client configured without
 * one read from address zero and killed the worker.
 *
 * eurl is decrypted in dims_handler, before any signature is checked, so this
 * needs no key and no signature. The NOKEY client in the test configuration is
 * exactly such a client.
 */
static void
test_eurl_without_a_client_secret(void)
{
    dims_response *response = dims_get("/dims3/NOKEY/resize/100x100/?eurl=AAAA");

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    CHECK(response->status >= 400,
          "a client with no secret cannot decrypt an eurl, got %ld",
          response->status);

    dims_response_free(response);
}

/*
 * apr_uri_parse leaves path NULL for a URL with no path, and
 * strrchr dereferences it. The legacy /dims/ handler reaches it. Checking
 * the pointer first.
 */
static void
test_source_url_without_path(void)
{
    dims_response *response = dims_get("/dims/" DIMS_TEST_CLIENT
                                       "/1/100/100/70/http://origin:8080");

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    CHECK(response->status >= 400,
          "a source URL with no path is an error, got %ld", response->status);

    dims_response_free(response);
}

/*
 * The Content-Disposition filename comes from the source URL and
 * is not escaped, so a quote breaks out of the parameter. The filename needs escaping.
 */
static void
test_content_disposition_is_escaped(void)
{
    /* %22 must reach ap_unescape_url intact, so the query is written by
     * hand. dims_urlencode would turn the percent into %25. */
    const char *raw_url = "http://origin:8080/grid.png";
    char *signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                           "resize/100x100/", raw_url, NULL, 0);
    char path[1024];
    dims_response *response;
    const char *value;

    snprintf(path, sizeof(path),
             "/dims4/%s/%s/%s/resize/100x100/?url=http%%3A%%2F%%2Forigin%%3A8080%%2F"
             "grid.png%%22evil%%22.png&download=1",
             DIMS_TEST_CLIENT, signature, DIMS_TEST_EXPIRES);

    response = dims_get(path);
    value = dims_header_raw(response, "Content-Disposition");

    if (value != NULL) {
        dims_test_logf("Content-Disposition: [%s]", value);
        CHECK(strstr(value, "evil\"") == NULL,
              "the filename has an unescaped quote: [%s]", value);
    }

    dims_response_free(response);
    free(signature);
}
/*
 * A filename with CRLF in it would split the response into two. Everything
 * outside printable ASCII is dropped before the value reaches the header.
 */
static void
test_content_disposition_drops_control_characters(void)
{
    const char *raw_url = "http://origin:8080/grid.png";
    char *signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                           "resize/100x100/", raw_url, NULL, 0);
    char path[1024];
    dims_response *response;
    const char *value;

    snprintf(path, sizeof(path),
             "/dims4/%s/%s/%s/resize/100x100/?url=http%%3A%%2F%%2Forigin%%3A8080%%2F"
             "grid.png%%0d%%0aX-Injected%%3A%%20yes&download=1",
             DIMS_TEST_CLIENT, signature, DIMS_TEST_EXPIRES);

    response = dims_get(path);

    CHECK(response->transport_error == NULL, "the worker must answer: %s",
          response->transport_error ? response->transport_error : "");
    CHECK(dims_header_value(response, "X-Injected") == NULL,
          "a header the filename asked for must not appear");

    value = dims_header_raw(response, "Content-Disposition");
    if (value != NULL) {
        dims_test_logf("%s", value);
        CHECK(strstr(value, "\r") == NULL && strstr(value, "\n") == NULL,
              "the value must hold no line break");
    }

    dims_response_free(response);
    free(signature);
}

const dims_test dims_tests_errors[] = {
    { "TestUnknownClient", test_unknown_client, NULL },
    { "TestMissingSource", test_missing_source, NULL },
    { "TestOriginFailureIsMapped", test_origin_failure_is_mapped,
      "the origin status is forwarded" },
    { "TestBadGeometry", test_bad_geometry,
      "every failure reports one status" },
    { "TestQualityOutOfRange", test_quality_out_of_range,
      "quality is not range checked" },
    { "TestShortParameterStartingWithOpti", test_short_parameter_starting_with_opti, NULL },
    { "TestParameterWithoutEquals", test_parameter_without_equals, NULL },
    { "TestShortEurl", test_short_eurl, NULL },
    { "TestEmptyEurl", test_empty_eurl, NULL },
    { "TestEurlWithoutAClientSecret", test_eurl_without_a_client_secret, NULL },
    { "TestSignedParameterWithoutEquals", test_signed_parameter_without_equals, NULL },
    { "TestSignedRequestWithoutAQueryString",
      test_signed_request_without_a_query_string, NULL },
    { "TestEndpointUnderAnotherLocation", test_endpoint_under_another_location,
      NULL },
    { "TestSourceUrlWithoutPath", test_source_url_without_path, NULL },
    { "TestContentDispositionIsEscaped", test_content_disposition_is_escaped, NULL },
    { "TestContentDispositionDropsControlCharacters",
      test_content_disposition_drops_control_characters, NULL },
    DIMS_TEST_END
};
