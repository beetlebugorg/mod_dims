/*
 * DimsOriginStatusMode, DimsStatusVerbose, and the source URL in the path.
 *
 * The main test server runs the shipped defaults, which forward whatever the
 * origin said and print every component version. The server on port 8005 sets
 * both directives the other way, and enables the sizer.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

static const char *
mapped_url(void)
{
    const char *from_env = getenv("DIMS_TEST_MAPPED_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8005";
}

/* A signed request for a fixture, sent to the server that maps statuses. */
static dims_response *
mapped_request(const char *fixture)
{
    char *url = dims_fixture_url(fixture);
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);
    char full[2048];
    dims_response *response;

    snprintf(full, sizeof(full), "%s%s", mapped_url(), path);
    response = dims_get_absolute(full);

    free(path);
    free(url);

    return response;
}

/* The same request against the shipped defaults. */
static dims_response *
default_request(const char *fixture)
{
    char *url = dims_fixture_url(fixture);
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);
    dims_response *response = dims_get(path);

    free(path);
    free(url);

    return response;
}

/*
 * Finding M2. The origin's status became the caller's status, which reports
 * whether a target exists and what it wanted. In map mode an origin failure is
 * one of three answers and says nothing else.
 */
static void
test_origin_error_forwards_by_default(void)
{
    dims_response *response = default_request("broken.png");

    CHECK_INT(response->status, 500, "the origin's own status, forwarded");

    dims_response_free(response);
}

static void
test_origin_error_maps_to_bad_gateway(void)
{
    dims_response *response = mapped_request("broken.png");

    CHECK_INT(response->status, 502, "an origin error under map");

    dims_response_free(response);
}

/* A missing source is 404 in both modes. The caller can act on that one. */
static void
test_missing_source_is_not_found_in_both_modes(void)
{
    dims_response *forwarded = default_request("missing.png");
    dims_response *mapped = mapped_request("missing.png");

    CHECK_INT(forwarded->status, 404, "a missing source, forwarded");
    CHECK_INT(mapped->status, 404, "a missing source under map");

    dims_response_free(forwarded);
    dims_response_free(mapped);
}

/* The origin sleeps past the download timeout, which is one second here. */
static void
test_timeout_maps_to_gateway_timeout(void)
{
    dims_response *response = mapped_request("slow.png");

    CHECK(response->transport_error == NULL, "the worker must answer: %s",
          response->transport_error ? response->transport_error : "");
    CHECK_INT(response->status, 504, "a download timeout under map");

    dims_response_free(response);
}

/* A source that works must still answer 200 under map. */
static void
test_map_serves_a_working_source(void)
{
    dims_response *response = mapped_request("grid.png");
    dims_image_size size;

    CHECK_INT(response->status, 200, "a working source under map");
    size = dims_must_size(response->body, response->body_len);
    CHECK_INT(size.width, 100, "width");

    dims_response_free(response);
}

/*
 * Map mode reinterprets a failure at the origin and nothing else. A malformed
 * geometry fails after a successful fetch, which leaves 200 on the request,
 * and calling that a bad gateway would blame the origin for the caller's
 * mistake.
 */
static void
test_map_leaves_a_module_failure_alone(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4("resize/not-a-size", url, NULL, NULL);
    char full[2048];
    dims_response *response;

    snprintf(full, sizeof(full), "%s%s", mapped_url(), path);
    response = dims_get_absolute(full);

    CHECK_INT(response->status, 500, "a malformed geometry under map");

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * Finding M17. The status page names every library a caller would need to
 * pick an exploit, and the shipped configuration exposes it with no access
 * control.
 */
static void
test_status_prints_versions_by_default(void)
{
    dims_response *response = dims_get("/dims-status/");

    CHECK_INT(response->status, 200, "the status handler");
    CHECK(response->body != NULL &&
              strstr((const char *) response->body, "ImageMagick version") != NULL,
          "the default prints the component versions");

    dims_response_free(response);
}

static void
test_status_hides_versions_when_asked(void)
{
    char full[256];
    dims_response *response;

    snprintf(full, sizeof(full), "%s/dims-status/", mapped_url());
    response = dims_get_absolute(full);

    CHECK_INT(response->status, 200, "the status handler");
    CHECK(response->body != NULL &&
              strstr((const char *) response->body, "ALIVE") != NULL,
          "the page still reports the server is alive");
    CHECK(response->body != NULL &&
              strstr((const char *) response->body, "version") == NULL,
          "DimsStatusVerbose off prints no version");
    CHECK(response->body != NULL &&
              strstr((const char *) response->body, "Successful requests") != NULL,
          "the counters stay");

    dims_response_free(response);
}

/*
 * Finding M18. The sizer takes its URL from the path. httpd collapses the
 * double slash, and the module searched for "http:/" alone, so an https source
 * was never found and the request failed as a bad URL.
 *
 * The origin speaks plain HTTP, so the https case cannot return an image. It
 * has to fail somewhere other than the URL parser, and a 400 says the parser
 * refused it before any connection.
 */
static void
test_sizer_reads_an_http_url_from_the_path(void)
{
    char full[512];
    dims_response *response;

    snprintf(full, sizeof(full), "%s/dims-sizer/http:/origin:8080/grid.png",
             mapped_url());
    response = dims_get_absolute(full);

    CHECK_INT(response->status, 200, "the sizer with an http source");
    CHECK(response->body != NULL &&
              strstr((const char *) response->body, "\"width\": 512") != NULL,
          "the sizer reports the width");

    dims_response_free(response);
}

static void
test_sizer_reads_an_https_url_from_the_path(void)
{
    char full[512];
    dims_response *response;

    snprintf(full, sizeof(full), "%s/dims-sizer/https:/origin:8080/grid.png",
             mapped_url());
    response = dims_get_absolute(full);

    CHECK(response->transport_error == NULL, "the worker must answer: %s",
          response->transport_error ? response->transport_error : "");
    CHECK(response->status != 400,
          "an https source in the path must reach the fetch, not the URL parser");

    dims_response_free(response);
}

/*
 * Finding M1, on the server that enables the sizer. The sizer consulted no
 * allowlist, so any caller could ask it to connect anywhere and learn whether
 * the answer decoded as an image.
 */
static void
test_sizer_applies_the_allowlist(void)
{
    char full[512];
    dims_response *response;

    snprintf(full, sizeof(full), "%s/dims-sizer/http:/notallowed:8080/grid.png",
             mapped_url());
    response = dims_get_absolute(full);

    CHECK(response->status != 200,
          "the sizer must refuse a host outside the allowlist");

    dims_response_free(response);
}

const dims_test dims_tests_origin_status[] = {
    { "TestOriginErrorForwardsByDefault", test_origin_error_forwards_by_default,
      NULL },
    { "TestOriginErrorMapsToBadGateway", test_origin_error_maps_to_bad_gateway,
      NULL },
    { "TestMissingSourceIsNotFoundInBothModes",
      test_missing_source_is_not_found_in_both_modes, NULL },
    { "TestTimeoutMapsToGatewayTimeout", test_timeout_maps_to_gateway_timeout,
      NULL },
    { "TestMapServesAWorkingSource", test_map_serves_a_working_source, NULL },
    { "TestMapLeavesAModuleFailureAlone", test_map_leaves_a_module_failure_alone,
      NULL },
    { "TestStatusPrintsVersionsByDefault", test_status_prints_versions_by_default,
      NULL },
    { "TestStatusHidesVersionsWhenAsked", test_status_hides_versions_when_asked,
      NULL },
    { "TestSizerReadsAnHttpUrlFromThePath",
      test_sizer_reads_an_http_url_from_the_path, NULL },
    { "TestSizerReadsAnHttpsUrlFromThePath",
      test_sizer_reads_an_https_url_from_the_path, NULL },
    { "TestSizerAppliesTheAllowlist", test_sizer_applies_the_allowlist, NULL },
    DIMS_TEST_END
};
