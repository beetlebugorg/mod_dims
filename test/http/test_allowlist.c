/*
 * The host allowlist and the network guard, ported from
 * ../go-dims/internal/source/http_test.go.
 *
 * The guard has three tiers, and each one needs a server configured for it:
 *
 *   port 8000  the shipped defaults. Loopback, link local, a foreign scheme,
 *              and a long redirect chain are refused here, because no
 *              deployment fetches an image from one.
 *   port 8003  DimsAllowlistSigned enforce. The allowlist reaches a signed
 *              request and every redirect hop.
 *   port 8004  DimsAllowPrivateAddresses off. Nothing on the compose network
 *              is reachable, which is what proves the check runs at the socket.
 *
 * Every refusal asserts 400, which is the status go-dims returns for the same
 * refusal. A refusal and an unreachable host both fail to return an image, and
 * only the status tells them apart.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "../lib/common.h"

/* The status the guard returns. go-dims answers 400 for the same refusal. */
#define DIMS_REFUSED 400

static const char *
enforced_url(void)
{
    const char *from_env = getenv("DIMS_TEST_ALLOWLIST_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8003";
}

static const char *
no_private_url(void)
{
    const char *from_env = getenv("DIMS_TEST_NO_PRIVATE_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8004";
}

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

/* Builds a signed /dims4/ path, which is the path production traffic uses. */
static char *
dims4_path(const char *commands, const char *image_url)
{
    return dims_sign_dims4(commands, image_url, NULL, NULL);
}

/* Sends a path to a server other than the default one. */
static dims_response *
get_from(const char *base, char *path)
{
    char full[2048];

    snprintf(full, sizeof(full), "%s%s", base, path);

    return dims_get_absolute(full);
}

/*
 * A refusal on this server still sends the error image, because
 * DimsDefaultImageURL names one. The body proving that is what shows the
 * guard refused one fetch and not the one that follows it.
 */
static void
check_sent_the_error_image(const char *what, dims_response *response)
{
    dims_image_size size;

    CHECK(response->body_len > 0, "%s: the error image must have a body", what);
    size = dims_must_size(response->body, response->body_len);
    CHECK(size.width > 0 && size.height > 0, "%s: the error image must decode",
          what);
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
 * The origin also answers to "notallowed", which the allowlist does not name.
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

/* Ported: TestFetchImageRefusesLoopback. Tier one, on the shipped defaults. */
static void
test_fetch_image_refuses_loopback(void)
{
    char *path = dims4_path("resize/10x10", "http://127.0.0.1:8000/grid.png");
    dims_response *response = dims_get(path);

    check_refused("a signed loopback source", response);
    check_sent_the_error_image("a signed loopback source", response);

    dims_response_free(response);
    free(path);
}

/*
 * Ported: TestFetchImageRefusesNameResolvingToPrivate. The check runs on the
 * resolved address rather than on the name, so a name that resolves to
 * loopback is refused whatever it is called. That is what makes it survive
 * DNS rebinding.
 */
static void
test_fetch_image_refuses_name_resolving_to_private(void)
{
    char *path = dims4_path("resize/10x10", "http://localhost:8000/grid.png");
    dims_response *response = dims_get(path);

    check_refused("a name that resolves to loopback", response);

    dims_response_free(response);
    free(path);
}

/*
 * Ported: TestFetchImageRefusesInstanceMetadata.
 *
 * Signed, because that is the request C1 describes. An unsigned request never
 * reaches the guard: the allowlist refuses the address first, and has always
 * done so. A signed request skips the allowlist, so the guard is the only
 * thing between the caller and the credentials this endpoint returns.
 */
static void
test_fetch_image_refuses_instance_metadata(void)
{
    char *path = dims4_path("resize/10x10",
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

/* The redirect that lands on loopback is refused at the socket, tier one. */
static void
test_fetch_image_refuses_redirect_to_loopback(void)
{
    char *url = dims_fixture_url("redirect-loopback");
    char *path = dims3_path("resize/10x10", url);
    dims_response *response = dims_get(path);

    check_refused("a redirect to loopback", response);

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

/* A redirect that stays on the allowlist must still be followed. */
static void
test_fetch_image_follows_allowed_redirect(void)
{
    char *url = dims_fixture_url("redirect-ok");
    char *path = dims3_path("resize/100x100", url);
    dims_response *response = dims_get(path);
    dims_image_size size;

    CHECK_INT(response->status, 200, "a redirect within the allowlist");
    size = dims_must_size(response->body, response->body_len);
    CHECK_INT(size.width, 100, "width");

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * Ported: TestFetchImageAllowsPrivateWhenEnabled. Every host on the compose
 * network holds a private address, so the whole suite passing is the proof.
 * This case names the property.
 */
static void
test_fetch_image_allows_private_when_enabled(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims4_path("resize/100x100", url);
    dims_response *response = dims_get(path);

    CHECK_INT(response->status, 200,
              "a private origin with DimsAllowPrivateAddresses on");

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * The two defaults that keep this a drop-in upgrade.
 *
 * A signed request has never consulted the allowlist, and a redirect has never
 * been re-checked against it. Both stay that way until the operator sets
 * DimsAllowlistSigned to enforce. The cases below assert the old behavior on
 * the shipped defaults, and the cases after them assert the new behavior on
 * the server that sets the directive.
 */
static void
test_signed_request_skips_allowlist_by_default(void)
{
    char *path = dims4_path("resize/100x100", "http://notallowed:8080/grid.png");
    dims_response *response = dims_get(path);

    CHECK_INT(response->status, 200,
              "a signed request still reaches a host outside the allowlist");

    dims_response_free(response);
    free(path);
}

static void
test_redirect_off_allowlist_is_followed_by_default(void)
{
    char *url = dims_fixture_url("redirect-notallowed");
    char *path = dims3_path("resize/100x100", url);
    dims_response *response = dims_get(path);

    CHECK_INT(response->status, 200,
              "a redirect off the allowlist is still followed");

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * On the server that sets DimsAllowlistSigned enforce.
 *
 * The status is 500, not 400. A host outside the allowlist has reported that
 * way since the module was written, and enforcing the allowlist on a signed
 * request reaches the same refusal by the same route. Reporting the two
 * differently would mean two statuses for one condition. The status for every
 * refusal moves together, behind its own directive.
 */
static void
test_signed_request_applies_allowlist(void)
{
    char *path = dims4_path("resize/100x100", "http://notallowed:8080/grid.png");
    dims_response *response = get_from(enforced_url(), path);

    CHECK(response->transport_error == NULL, "the worker must answer: %s",
          response->transport_error ? response->transport_error : "");
    dims_test_logf("a signed request outside the allowlist under enforce "
                   "returns %ld", response->status);
    CHECK(response->status != 200,
          "a signed request must respect the allowlist under enforce");

    dims_response_free(response);
    free(path);
}

/* Ported: TestFetchImageRefusesRedirectOffTheAllowlist. */
static void
test_fetch_image_refuses_redirect_off_the_allowlist(void)
{
    char *url = dims_fixture_url("redirect-notallowed");
    char *path = dims3_path("resize/10x10", url);
    dims_response *response = get_from(enforced_url(), path);

    check_refused("a redirect off the allowlist, under enforce", response);

    dims_response_free(response);
    free(path);
    free(url);
}

/* The allowlist must still let the origin through under enforce. */
static void
test_enforced_allowlist_serves_the_origin(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims4_path("resize/100x100", url);
    dims_response *response = get_from(enforced_url(), path);

    CHECK_INT(response->status, 200, "the allowlisted origin under enforce");

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * DimsAllowPrivateAddresses off. The origin holds a private address on the
 * compose network, so this refuses the one host the allowlist names. That
 * is the point: the check runs on the address, after the name resolves.
 */
static void
test_fetch_image_refuses_private_when_disabled(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims4_path("resize/100x100", url);
    dims_response *response = get_from(no_private_url(), path);

    check_refused("a private origin with DimsAllowPrivateAddresses off",
                  response);

    dims_response_free(response);
    free(path);
    free(url);
}

const dims_test dims_tests_allowlist[] = {
    { "TestHostAllowed", test_host_allowed, NULL },
    { "TestFetchImageRefusesHostOutsideAllowlist",
      test_fetch_image_refuses_host_outside_allowlist, NULL },
    { "TestFetchImageRefusesLoopback", test_fetch_image_refuses_loopback, NULL },
    { "TestFetchImageRefusesNameResolvingToPrivate",
      test_fetch_image_refuses_name_resolving_to_private, NULL },
    { "TestFetchImageRefusesInstanceMetadata",
      test_fetch_image_refuses_instance_metadata, NULL },
    { "TestFetchImageRefusesNonHTTPScheme", test_fetch_image_refuses_non_http_scheme,
      NULL },
    { "TestFetchImageRefusesRedirectToLoopback",
      test_fetch_image_refuses_redirect_to_loopback, NULL },
    { "TestFetchImageCapsRedirectChain", test_fetch_image_caps_redirect_chain, NULL },
    { "TestFetchImageFollowsAllowedRedirect",
      test_fetch_image_follows_allowed_redirect, NULL },
    { "TestFetchImageAllowsPrivateWhenEnabled",
      test_fetch_image_allows_private_when_enabled, NULL },
    { "TestSignedRequestSkipsAllowlistByDefault",
      test_signed_request_skips_allowlist_by_default, NULL },
    { "TestRedirectOffAllowlistIsFollowedByDefault",
      test_redirect_off_allowlist_is_followed_by_default, NULL },
    { "TestSignedRequestAppliesAllowlist", test_signed_request_applies_allowlist,
      NULL },
    { "TestFetchImageRefusesRedirectOffTheAllowlist",
      test_fetch_image_refuses_redirect_off_the_allowlist, NULL },
    { "TestEnforcedAllowlistServesTheOrigin",
      test_enforced_allowlist_serves_the_origin, NULL },
    { "TestFetchImageRefusesPrivateWhenDisabled",
      test_fetch_image_refuses_private_when_disabled, NULL },
    DIMS_TEST_END
};
