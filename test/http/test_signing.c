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
#include "../lib/fixtures.h"
#include "../lib/prometheus.h"

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
 * overlay and the request has one.
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
 * has no query string at all must still answer. Confirming the read itself needs
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

/* -- The shared fixtures ------------------------------------------------ */
/*
 * test/fixtures/signing.tsv holds the signatures the C library, the Go client,
 * and the Java client all produce. This requests every one of them against the
 * running module. A value all three reproduce and the module refuses fails
 * here and nowhere else.
 */

static const char *
dims5_server(void)
{
    const char *from_env = getenv("DIMS_TEST_DIMS5_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8007";
}

static dims_response *
scrape_metrics(void)
{
    char url[512];

    snprintf(url, sizeof(url), "%s/metrics", dims_base_url());

    return dims_get_absolute(url);
}

typedef struct {
    int sent;
    int skipped;
} fixture_run;

static void
request_fixture(const dims_fixture *f, void *data)
{
    fixture_run *run = data;
    int is_dims5 = dims_fixture_is_dims5(f);
    char url[DIMS_FIXTURE_FIELD_MAX + 256];
    dims_response *response;

    /* A record the signer refuses has no URL to send. */
    if (f->has_error) {
        run->skipped++;
        return;
    }

    /* The module reads a fixed seven characters past the start of the path, so
     * it serves no prefix but its own. */
    if (strncmp(f->expected, "/dims4/", 7) != 0 &&
            strncmp(f->expected, "/dims5/", 7) != 0) {
        run->skipped++;
        return;
    }

    /* The module decrypts eurl and uses it as the image URL. A ciphertext
     * holds a fresh nonce, so the file has none to send. */
    if (strstr(f->expected, "&eurl=") != NULL) {
        run->skipped++;
        return;
    }

    snprintf(url, sizeof(url), "%s%s",
             is_dims5 ? dims5_server() : dims_base_url(), f->expected);

    response = dims_get_absolute(url);

    CHECK(response->transport_error == NULL, "%s: %s", f->name,
          response->transport_error ? response->transport_error : "");

    run->sent++;
    dims_response_free(response);
}

static double
signature_count(const dims_response *metrics, const char *endpoint,
                const char *result)
{
    char prefix[128];

    snprintf(prefix, sizeof(prefix),
             "dims_signature_checks_total{endpoint=\"%s\",result=\"%s\"}",
             endpoint, result);

    return dims_prom_value(metrics, prefix);
}

static void
test_every_fixture_url_verifies(void)
{
    dims_response *before = scrape_metrics();
    double ok_dims4 = signature_count(before, "dims4", "ok");
    double ok_dims5 = signature_count(before, "dims5", "ok");
    double bad_dims4 = signature_count(before, "dims4", "mismatch");
    double bad_dims5 = signature_count(before, "dims5", "mismatch");
    fixture_run run = { 0, 0 };
    dims_response *after;
    int count;

    CHECK_INT(before->status, 200, "the metrics endpoint");

    count = dims_fixtures_read(request_fixture, &run);
    CHECK(count > 0, "cannot read %s", dims_fixtures_path());
    CHECK(run.sent > 0, "the file holds a URL the module serves");

    after = scrape_metrics();

    CHECK(signature_count(after, "dims4", "mismatch") == bad_dims4,
          "no /dims4/ fixture URL is refused, %g became %g", bad_dims4,
          signature_count(after, "dims4", "mismatch"));
    CHECK(signature_count(after, "dims5", "mismatch") == bad_dims5,
          "no /dims5/ fixture URL is refused, %g became %g", bad_dims5,
          signature_count(after, "dims5", "mismatch"));

    CHECK(signature_count(after, "dims4", "ok") +
                  signature_count(after, "dims5", "ok") -
                  ok_dims4 - ok_dims5 == run.sent,
          "every one of the %d URLs verified", run.sent);

    dims_response_free(before);
    dims_response_free(after);
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
    { "TestEveryFixtureUrlVerifies", test_every_fixture_url_verifies, NULL },
    DIMS_TEST_END
};
