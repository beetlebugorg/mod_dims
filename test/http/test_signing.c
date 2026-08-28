/*
 * /dims4/ signature cases. The first two are ported from
 * ../go-dims/internal/v4/request_test.go. The rest record findings C5, C6,
 * and M22, which cannot be fixed on /dims4/ and are closed on /dims5/ by
 * PRs 19 and 20.
 *
 * mod_dims signs the command path with its trailing slash, because
 * dims_handle_request signs whatever ap_getword leaves. Every direct call to
 * dims_signature_dims4 below passes that form.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "../lib/common.h"

#define COMMANDS "resize/100x100"
#define SIGNED_COMMANDS "resize/100x100/"

static void
test_signed_url_validates(void)
{
    dims_response *response = dims_request_ops(COMMANDS, "grid.png");

    CHECK_INT(response->status, 200, "a correctly signed URL");
    dims_response_free(response);
}

/*
 * go-dims models the mod_dims signature in modDimsSignature and asserts the
 * two agree. This is the same assertion from the other side: the digest this
 * suite computes is the one the server accepts.
 */
static void
test_legacy_signature_matches_mod_dims(void)
{
    char *url = dims_fixture_url("grid.png");
    char *signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                           SIGNED_COMMANDS, url, NULL, 0);
    char *path;
    dims_response *response;

    CHECK(signature != NULL, "the digest must compute");

    path = dims_sign_dims4_with(signature, DIMS_TEST_EXPIRES, COMMANDS, url, NULL, NULL);
    response = dims_get(path);

    CHECK_INT(response->status, 200, "the digest this suite computes");

    dims_response_free(response);
    free(path);
    free(signature);
    free(url);
}

static void
test_wrong_signature_rejected(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4_with("ffffff", DIMS_TEST_EXPIRES, COMMANDS, url,
                                      NULL, NULL);
    dims_response *response = dims_get(path);

    CHECK(response->status != 200, "a wrong signature must not return 200");

    dims_response_free(response);
    free(path);
    free(url);
}

static void
test_expired_signature_rejected(void)
{
    char *url = dims_fixture_url("grid.png");
    char *signature = dims_signature_dims4("1000000000", DIMS_TEST_SECRET,
                                           SIGNED_COMMANDS, url, NULL, 0);
    char *path = dims_sign_dims4_with(signature, "1000000000", COMMANDS, url,
                                      NULL, NULL);
    dims_response *response = dims_get(path);

    CHECK(response->status != 200, "an expired signature must not return 200");

    dims_response_free(response);
    free(path);
    free(signature);
    free(url);
}

/*
 * strncasecmp compares six characters, so a digest that agrees on
 * the first six and differs after them is accepted. Twenty-four bits gate the
 * fetch. A full-length HMAC is the fix.
 */
static void
test_signature_is_full_length(void)
{
    char *url = dims_fixture_url("grid.png");
    char *signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                           SIGNED_COMMANDS, url, NULL, 0);
    char *path;
    dims_response *response;

    /* Keep the first six characters and replace the rest. */
    memset(signature + 6, 'a', strlen(signature) - 6);

    path = dims_sign_dims4_with(signature, DIMS_TEST_EXPIRES, COMMANDS, url, NULL, NULL);
    response = dims_get(path);

    dims_test_logf("a digest correct in six characters returns %ld", response->status);
    CHECK(response->status != 200,
          "only the first six characters are compared, so 24 bits gate the fetch");

    dims_response_free(response);
    free(path);
    free(signature);
    free(url);
}

/*
 * overlay is signed only when _keys names it, so one valid
 * signature accepts any overlay. The signature below is computed without
 * overlay and the request carries one.
 */
static void
test_signature_covers_every_parameter(void)
{
    char *url = dims_fixture_url("grid.png");
    char *overlay = dims_fixture_url("overlay.png");
    char *encoded = dims_urlencode(overlay);
    char extra[1024];
    char *signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                           "watermark/0.2,0.5,se/", url, NULL, 0);
    char *path;
    dims_response *response;

    snprintf(extra, sizeof(extra), "overlay=%s", encoded);
    path = dims_sign_dims4_with(signature, DIMS_TEST_EXPIRES, "watermark/0.2,0.5,se",
                                url, extra, NULL);
    response = dims_get(path);

    dims_test_logf("an unsigned overlay returns %ld", response->status);
    CHECK(response->status != 200,
          "overlay sits outside the signature, so an unsigned value is accepted");

    dims_response_free(response);
    free(path);
    free(signature);
    free(encoded);
    free(overlay);
    free(url);
}

/*
 * optimizeResize changes how much work the server does per
 * request and is not part of the signature.
 */
static void
test_unsigned_parameters_are_refused(void)
{
    char *url = dims_fixture_url("grid.png");
    char *signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                           SIGNED_COMMANDS, url, NULL, 0);
    char *path = dims_sign_dims4_with(signature, DIMS_TEST_EXPIRES, COMMANDS, url,
                                      "optimizeResize=4.0", NULL);
    dims_response *response = dims_get(path);

    dims_test_logf("an unsigned optimizeResize returns %ld", response->status);
    CHECK(response->status != 200, "optimizeResize sits outside the signature");

    dims_response_free(response);
    free(path);
    free(signature);
    free(url);
}

/*
 * The uninitialized read below is not a wrong answer, so it is not
 * observable from outside. This case is a regression guard: the form that
 * carries no query string at all must still answer. Confirming C4 itself needs
 * a build with -fsanitize=address, which CI runs.
 */
static void
test_no_query_string_answers(void)
{
    char *url = dims_fixture_url("grid.png");
    char *signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                           SIGNED_COMMANDS, url, NULL, 0);
    char path[2048];
    dims_response *response;

    snprintf(path, sizeof(path), "/dims4/%s/%s/%s/resize/100x100/%s",
             DIMS_TEST_CLIENT, signature, DIMS_TEST_EXPIRES, url);

    response = dims_get(path);

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    CHECK(response->status != 0, "the worker must answer with a status");

    dims_response_free(response);
    free(signature);
    free(url);
}

const dims_test dims_tests_signing[] = {
    { "TestSignedUrlValidates", test_signed_url_validates, NULL },
    { "TestLegacySignatureMatchesModDims", test_legacy_signature_matches_mod_dims, NULL },
    { "TestWrongSignatureRejected", test_wrong_signature_rejected, NULL },
    { "TestExpiredSignatureRejected", test_expired_signature_rejected, NULL },
    { "TestSignatureIsFullLength", test_signature_is_full_length,
      "the signature compares six characters" },
    { "TestSignatureCoversEveryParameter", test_signature_covers_every_parameter,
      "overlay is signed only when _keys names it" },
    { "TestUnsignedParametersAreRefused", test_unsigned_parameters_are_refused,
      "optimizeResize is never signed" },
    { "TestNoQueryStringAnswers", test_no_query_string_answers, NULL },
    DIMS_TEST_END
};
