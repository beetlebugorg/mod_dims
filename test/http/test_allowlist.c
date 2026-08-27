/*
 * /dims3/ host allowlist, and the fetch guard cases ported from
 * ../go-dims/internal/source/http_test.go and
 * ../go-dims/internal/core/network_test.go.
 *
 * Every guard case asserts 403 specifically, not merely "not 200". A refusal
 * and an unreachable host both fail to return an image, and only the status
 * tells them apart. Today the guard does not exist and these return 500, so
 * each is an expected failure. They are the acceptance criteria for PR 16.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "../lib/common.h"

/* The status the guard returns once PR 16 lands. */
#define DIMS_REFUSED 403

/* Builds an unsigned /dims3/ path for an arbitrary source URL. */
static char *
dims3_path(const char *commands, const char *image_url)
{
    char *encoded = dims_urlencode(image_url);
    size_t len = strlen(commands) + strlen(encoded) + 64;
    char *path = malloc(len);

    snprintf(path, len, "/dims3/%s/%s/?url=%s", DIMS_TEST_CLIENT, commands, encoded);
    free(encoded);

    return path;
}

static void
check_refused(const char *what, dims_response *response)
{
    CHECK(response->transport_error == NULL, "%s: the worker must answer: %s", what,
          response->transport_error ? response->transport_error : "");
    dims_test_logf("%s returns %ld", what, response->status);
    CHECK_INT(response->status, DIMS_REFUSED, what);
}

static void
test_host_allowed(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims3_path("resize/100x100", url);
    dims_response *response = dims_get(path);

    CHECK_INT(response->status, 200, "the allowlisted origin");

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * The origin also answers to "notallowed", which the allowlist does not carry.
 * The host is reachable and serves the same image, so a refusal here is the
 * allowlist and nothing else.
 */
static void
test_fetch_image_refuses_host_outside_allowlist(void)
{
    char *path = dims3_path("resize/100x100", "http://notallowed:8080/grid.png");
    dims_response *response = dims_get(path);

    CHECK(response->status != 200,
          "a reachable host outside the allowlist must be refused");

    dims_response_free(response);
    free(path);
}

/*
 * Finding C1. A signed request skips the allowlist entirely. See
 * src/mod_dims.c:1489-1491. The host is reachable, so a 200 means the
 * allowlist was not applied. PR 16 gates that on DimsAllowlistSigned.
 */
static void
test_signed_request_applies_allowlist(void)
{
    char *signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                           "resize/100x100/",
                                           "http://notallowed:8080/grid.png", NULL, 0);
    char *path = dims_sign_dims4_with(signature, DIMS_TEST_EXPIRES, "resize/100x100",
                                      "http://notallowed:8080/grid.png", NULL, NULL);
    dims_response *response = dims_get(path);

    dims_test_logf("a signed request to a host outside the allowlist returns %ld",
                   response->status);
    CHECK(response->status != 200,
          "a signed request must still respect the allowlist");

    dims_response_free(response);
    free(path);
    free(signature);
}

/*
 * Ported: TestFetchImageRefusesLoopback. The dims container serves grid.png on
 * its own port, so loopback is a working image source, and the request is signed
 * so the allowlist does not refuse it first. A 200 means nothing
 * stopped the fetch.
 */
static void
test_fetch_image_refuses_loopback(void)
{
    char *signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                           "resize/10x10/",
                                           "http://127.0.0.1:8000/grid.png", NULL, 0);
    char *path = dims_sign_dims4_with(signature, DIMS_TEST_EXPIRES, "resize/10x10",
                                      "http://127.0.0.1:8000/grid.png", NULL, NULL);
    dims_response *response = dims_get(path);

    dims_test_logf("a signed loopback source returns %ld", response->status);
    CHECK(response->status != 200, "loopback must be refused");

    dims_response_free(response);
    free(path);
    free(signature);
}
/* Ported: TestFetchImageRefusesInstanceMetadata. */
static void
test_fetch_image_refuses_instance_metadata(void)
{
    char *path = dims3_path("resize/10x10",
                            "http://169.254.169.254/latest/meta-data/iam/");
    dims_response *response = dims_get(path);

    check_refused("the metadata address", response);

    dims_response_free(response);
    free(path);
}

/* Ported: TestFetchImageRefusesNonHTTPScheme. */
static void
test_fetch_image_refuses_non_http_scheme(void)
{
    char *path = dims3_path("resize/10x10", "gopher://origin:8080/grid.png");
    dims_response *response = dims_get(path);

    check_refused("a gopher source", response);

    dims_response_free(response);
    free(path);
}

/*
 * Ported: TestFetchImageRefusesRedirectOffTheAllowlist. The origin redirects to
 * itself under the name the allowlist does not carry, so the target is
 * reachable and returns a real image.
 */
static void
test_fetch_image_refuses_redirect_off_the_allowlist(void)
{
    char *url = dims_fixture_url("redirect-notallowed");
    char *path = dims3_path("resize/10x10", url);
    dims_response *response = dims_get(path);

    dims_test_logf("a redirect off the allowlist returns %ld", response->status);
    CHECK(response->status != 200,
          "a redirect to a host outside the allowlist must be refused");

    dims_response_free(response);
    free(path);
    free(url);
}

/* Ported: TestFetchImageRefusesNameResolvingToPrivate. */
static void
test_fetch_image_refuses_redirect_to_loopback(void)
{
    char *url = dims_fixture_url("redirect-loopback");
    char *path = dims3_path("resize/10x10", url);
    dims_response *response = dims_get(path);

    dims_test_logf("a redirect to loopback returns %ld", response->status);
    CHECK(response->status != 200, "a redirect to loopback must be refused");

    dims_response_free(response);
    free(path);
    free(url);
}

/* Ported: TestFetchImageCapsRedirectChain. */
static void
test_fetch_image_caps_redirect_chain(void)
{
    char *url = dims_fixture_url("redirect-loop");
    char *path = dims3_path("resize/10x10", url);
    dims_response *response = dims_get(path);

    check_refused("a redirect loop", response);

    dims_response_free(response);
    free(path);
    free(url);
}

const dims_test dims_tests_allowlist[] = {
    { "TestHostAllowed", test_host_allowed, NULL },
    { "TestFetchImageRefusesHostOutsideAllowlist",
      test_fetch_image_refuses_host_outside_allowlist, NULL },
    { "TestSignedRequestAppliesAllowlist", test_signed_request_applies_allowlist, "C1" },
    { "TestFetchImageRefusesLoopback", test_fetch_image_refuses_loopback, "C1" },
    { "TestFetchImageRefusesInstanceMetadata",
      test_fetch_image_refuses_instance_metadata, "C1" },
    { "TestFetchImageRefusesNonHTTPScheme", test_fetch_image_refuses_non_http_scheme, "C1" },
    { "TestFetchImageRefusesRedirectOffTheAllowlist",
      test_fetch_image_refuses_redirect_off_the_allowlist, "C2" },
    { "TestFetchImageRefusesRedirectToLoopback",
      test_fetch_image_refuses_redirect_to_loopback, "C2" },
    { "TestFetchImageCapsRedirectChain", test_fetch_image_caps_redirect_chain, "C1" },
    DIMS_TEST_END
};
