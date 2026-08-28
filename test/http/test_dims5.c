/*
 * The /dims5/ endpoint.
 *
 * The server on port 8007 sets a signing key. No other server serves this
 * endpoint, because it takes one key rather than a per client secret.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

static const char *
dims5_url(void)
{
    const char *from_env = getenv("DIMS_TEST_DIMS5_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8007";
}

static dims_response *
dims5_get(const char *path)
{
    char full[2048];

    snprintf(full, sizeof(full), "%s%s", dims5_url(), path);

    return dims_get_absolute(full);
}

static dims_response *
dims5_request(const char *commands, const char *fixture, const char *extra)
{
    char *url = dims_fixture_url(fixture);
    char *path = dims_sign_dims5(commands, url, extra);
    dims_response *response = dims5_get(path);

    free(path);
    free(url);

    return response;
}

static void
test_dims5_resize(void)
{
    dims_response *response = dims5_request("resize/100x100", "grid.png", NULL);
    dims_image_size size;

    CHECK_INT(response->status, 200, "a signed request");
    size = dims_must_size(response->body, response->body_len);
    CHECK_INT(size.width, 100, "width");
    CHECK_INT(size.height, 100, "height");

    dims_response_free(response);
}

/* Several commands run left to right, as they do everywhere else. */
static void
test_dims5_several_commands(void)
{
    dims_response *response = dims5_request("resize/100x100/format/png",
                                            "grid.png", NULL);
    dims_image_size size;

    CHECK_INT(response->status, 200, "two commands");
    size = dims_must_size(response->body, response->body_len);
    CHECK_INT(size.width, 100, "width");

    dims_response_free(response);
}

/* A digest that does not match is refused. */
static void
test_dims5_wrong_signature(void)
{
    char *url = dims_fixture_url("grid.png");
    char *encoded = dims_urlencode(url);
    char path[2048];
    dims_response *response;

    snprintf(path, sizeof(path),
             "/dims5/resize/100x100/?url=%s&sig=%s", encoded,
             "0000000000000000000000000000000000000000000000000000000000000000");
    response = dims5_get(path);

    CHECK(response->status >= 400, "a wrong signature, got %ld", response->status);

    dims_response_free(response);
    free(encoded);
    free(url);
}

static void
test_dims5_without_a_signature(void)
{
    char *url = dims_fixture_url("grid.png");
    char *encoded = dims_urlencode(url);
    char path[2048];
    dims_response *response;

    snprintf(path, sizeof(path), "/dims5/resize/100x100/?url=%s", encoded);
    response = dims5_get(path);

    CHECK(response->status >= 400, "no signature, got %ld", response->status);

    dims_response_free(response);
    free(encoded);
    free(url);
}

/* A signature covers the commands, so changing them invalidates it. */
static void
test_dims5_altered_commands(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims5("resize/100x100", url, NULL);
    char *altered = strstr(path, "100x100");
    dims_response *response;

    CHECK(altered != NULL, "the path holds the geometry");
    if (altered != NULL) {
        memcpy(altered, "200x200", 7);
    }

    response = dims5_get(path);
    CHECK(response->status >= 400,
          "an altered geometry must be refused, got %ld", response->status);

    dims_response_free(response);
    free(path);
    free(url);
}

/* A signature covers the image URL too. */
static void
test_dims5_altered_url(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims5("resize/100x100", url, NULL);
    char *altered = strstr(path, "grid.png");
    dims_response *response;

    CHECK(altered != NULL, "the path holds the fixture name");
    if (altered != NULL) {
        memcpy(altered, "cmyk.jpg", 8);
    }

    response = dims5_get(path);
    CHECK(response->status >= 400,
          "an altered source must be refused, got %ld", response->status);

    dims_response_free(response);
    free(path);
    free(url);
}

/*
 * Every parameter takes part in the signature apart from the five that are
 * excluded, so the overlay a watermark composites cannot be swapped.
 */
static void
test_dims5_signs_the_overlay(void)
{
    char *url = dims_fixture_url("grid.png");
    char *overlay = dims_fixture_url("overlay.png");
    char *encoded = dims_urlencode(overlay);
    char extra[1024];
    char *path;
    char *altered;
    dims_response *response;

    snprintf(extra, sizeof(extra), "overlay=%s", encoded);
    path = dims_sign_dims5("watermark/0.2,0.5,se", url, extra);

    response = dims5_get(path);
    CHECK_INT(response->status, 200, "a signed watermark");
    dims_response_free(response);

    /* The same request with a different overlay. */
    altered = strstr(path, "overlay.png");
    CHECK(altered != NULL, "the path holds the overlay name");
    if (altered != NULL) {
        memcpy(altered, "portrait.jpg", 11);
    }

    response = dims5_get(path);
    CHECK(response->status >= 400,
          "an altered overlay must be refused, got %ld", response->status);

    dims_response_free(response);
    free(path);
    free(encoded);
    free(overlay);
    free(url);
}

/* download takes no part, so it can be added to a signed URL. */
static void
test_dims5_download_is_not_signed(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims5("resize/100x100", url, NULL);
    char with_download[2048];
    dims_response *response;

    snprintf(with_download, sizeof(with_download), "%s&download=1", path);
    response = dims5_get(with_download);

    CHECK_INT(response->status, 200, "download added to a signed URL");
    CHECK(dims_header_value(response, "Content-Disposition") != NULL,
          "the response must ask to download");

    dims_response_free(response);
    free(path);
    free(url);
}

/* A line break in a signed field could stand in for two fields. */
static void
test_dims5_refuses_a_control_character(void)
{
    dims_response *response = dims5_get(
        "/dims5/resize/100x100/?url=http%3A%2F%2Forigin%3A8080%2Fgrid.png%0Aevil"
        "&sig=0000000000000000000000000000000000000000000000000000000000000000");

    CHECK(response->transport_error == NULL, "the worker must answer: %s",
          response->transport_error ? response->transport_error : "");
    CHECK(response->status >= 400, "a control character, got %ld", response->status);

    dims_response_free(response);
}

/*
 * eurl hides the source from a public caller. The key comes from the same
 * signing key, through HKDF-SHA256.
 *
 * The value here was produced by an independent implementation of the scheme,
 * so a change to the derivation, the salt, or the cipher shows up as a
 * decryption failure rather than passing unnoticed.
 */
static void
test_dims5_eurl(void)
{
    const char *eurl = getenv("DIMS_TEST_EURL");
    char *encoded;
    char *signature;
    char path[4096];
    char extra[2048];
    dims_response *response;

    CHECK(eurl != NULL && *eurl != '\0',
          "DIMS_TEST_EURL must be set, or this case checks nothing");
    if (eurl == NULL || *eurl == '\0') {
        return;
    }

    encoded = dims_urlencode(eurl);
    snprintf(extra, sizeof(extra), "eurl=%s", encoded);

    /* eurl takes no part in the signature, and the decrypted URL is what the
     * message covers. */
    signature = dims_signature_dims5(DIMS_TEST_SIGNING_KEY, "resize/100x100/",
                                     "http://origin:8080/grid.png", "");
    snprintf(path, sizeof(path), "/dims5/resize/100x100/?%s&sig=%s", extra,
             signature);

    response = dims5_get(path);

    CHECK_INT(response->status, 200, "an encrypted source");

    dims_response_free(response);
    free(signature);
    free(encoded);
}

/*
 * A signature computed elsewhere.
 *
 * The value below came from an independent implementation of the scheme,
 * written from the specification: HMAC-SHA256 over the commands, the image
 * URL, and the canonical query, one per line, with the query built by a
 * standard encoder rather than by this project's code.
 *
 * That is what makes it worth asserting. A signature this module computes
 * against itself proves only that it agrees with itself. This one fails if
 * the message construction, the parameter ordering, or the percent encoding
 * drifts from what another implementation produces.
 */
static void
test_dims5_accepts_a_signature_computed_elsewhere(void)
{
    dims_response *response = dims5_get(
        "/dims5/watermark/0.2,0.5,se/"
        "?overlay=http%3A%2F%2Forigin%3A8080%2Foverlay.png"
        "&url=http%3A%2F%2Forigin%3A8080%2Fgrid.png"
        "&sig=ecd30f9f48391ac8eb423f314913575132d401c082f9eb510d958c305d5a094d");
    dims_image_size size;

    CHECK_INT(response->status, 200, "a signature computed elsewhere");
    size = dims_must_size(response->body, response->body_len);
    CHECK_INT(size.width, 512, "width");

    dims_response_free(response);
}

/*
 * A failed request answers with a drawn image at the size the commands asked
 * for, rather than one fetched from somewhere.
 */
static void
test_dims5_error_image(void)
{
    dims_response *response = dims5_request("resize/100x100", "missing.png", NULL);
    dims_image_size size;

    CHECK(response->body_len > 0, "a failure must still answer with an image");
    size = dims_must_size(response->body, response->body_len);

    dims_test_logf("a missing source answers %ld with %ldx%ld",
                   response->status, size.width, size.height);
    CHECK_INT(size.width, 100, "width");
    CHECK_INT(size.height, 100, "height");

    dims_response_free(response);
}

/* Without a geometry there is nothing to match, so a square is drawn. */
static void
test_dims5_error_image_without_a_geometry(void)
{
    dims_response *response = dims5_request("strip/true", "missing.png", NULL);
    dims_image_size size;

    CHECK(response->body_len > 0, "a failure must still answer with an image");
    size = dims_must_size(response->body, response->body_len);
    CHECK_INT(size.width, 512, "width");
    CHECK_INT(size.height, 512, "height");

    dims_response_free(response);
}

/* /dims5/ returns 304 for a matching ETag, the same as /dims4/. */
static void
test_dims5_conditional_request(void)
{
    dims_response *first = dims5_request("resize/100x100", "grid.png", NULL);
    const char *etag = dims_header_value(first, "ETag");
    char header[512];
    const char *headers[1];
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims5("resize/100x100", url, NULL);
    char full[2048];
    dims_response *second;

    CHECK(etag != NULL, "the first response must have an ETag");
    snprintf(header, sizeof(header), "If-None-Match: %s", etag);
    headers[0] = header;

    snprintf(full, sizeof(full), "%s%s", dims5_url(), path);
    second = dims_get_absolute_with_headers(full, headers, 1);

    CHECK_INT(second->status, 304, "a request with a matching ETag");
    CHECK_INT((long) second->body_len, 0, "the body length of a 304");

    dims_response_free(first);
    dims_response_free(second);
    free(path);
    free(url);
}

const dims_test dims_tests_dims5[] = {
    { "TestDims5Resize", test_dims5_resize, NULL },
    { "TestDims5SeveralCommands", test_dims5_several_commands, NULL },
    { "TestDims5WrongSignature", test_dims5_wrong_signature, NULL },
    { "TestDims5WithoutASignature", test_dims5_without_a_signature, NULL },
    { "TestDims5AlteredCommands", test_dims5_altered_commands, NULL },
    { "TestDims5AlteredUrl", test_dims5_altered_url, NULL },
    { "TestDims5SignsTheOverlay", test_dims5_signs_the_overlay, NULL },
    { "TestDims5DownloadIsNotSigned", test_dims5_download_is_not_signed, NULL },
    { "TestDims5RefusesAControlCharacter",
      test_dims5_refuses_a_control_character, NULL },
    { "TestDims5Eurl", test_dims5_eurl, NULL },
    { "TestDims5AcceptsASignatureComputedElsewhere",
      test_dims5_accepts_a_signature_computed_elsewhere, NULL },
    { "TestDims5ErrorImage", test_dims5_error_image, NULL },
    { "TestDims5ErrorImageWithoutAGeometry",
      test_dims5_error_image_without_a_geometry, NULL },
    { "TestDims5ConditionalRequest", test_dims5_conditional_request, NULL },
    DIMS_TEST_END
};
