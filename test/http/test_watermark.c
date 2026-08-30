/*
 * The watermark command. go-dims TestReduceOpacityMaterializes is a libvips
 * lifetime test with no mod_dims equivalent, so this covers the composite
 * instead.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

/* watermark reads the overlay from a query parameter, so it needs the signed
 * form with _keys. */
static dims_response *
watermark_request(const char *args, const char *overlay_path)
{
    char *url = dims_fixture_url("grid.png");
    char *overlay = dims_fixture_url(overlay_path);
    char *encoded = dims_urlencode(overlay);
    char extra[1024];
    char commands[128];
    char *path;
    dims_response *response;

    snprintf(commands, sizeof(commands), "watermark/%s", args);
    snprintf(extra, sizeof(extra), "overlay=%s", encoded);

    path = dims_sign_dims4(commands, url, extra, "overlay");
    response = dims_get(path);

    free(path);
    free(encoded);
    free(overlay);
    free(url);

    return response;
}

static void
test_watermark(void)
{
    dims_response *response = watermark_request("0.2,0.5,se", "overlay.png");
    dims_image_size size;

    CHECK_INT(response->status, 200, "a signed watermark request");
    size = dims_must_size(response->body, response->body_len);
    CHECK_INT(size.width, 512, "width");
    CHECK_INT(size.height, 512, "height");

    assert_golden("grid.TestWatermark", response->body, response->body_len, ".png");
    dims_response_free(response);
}

/*
 * opacity, size, and gravity are read whether or not their token was present,
 * so a short argument list uses uninitialized memory. The values
 * turn out to be stable across requests, so the defect is not observable from
 * outside; confirming it needs valgrind or -fsanitize=memory, which CI runs.
 * This case guards the property that two identical requests agree.
 */
static void
test_watermark_short_arguments_are_stable(void)
{
    dims_response *first = watermark_request("0.2", "overlay.png");
    dims_response *second = watermark_request("0.2", "overlay.png");

    CHECK_INT(first->status, 200, "watermark with one argument");
    CHECK(first->body_len == second->body_len,
          "two identical requests must return the same bytes: %zu then %zu",
          first->body_len, second->body_len);

    dims_response_free(first);
    dims_response_free(second);
}

/*
 * An overlay with no slash names no file. The operation refuses it, and the
 * server answers with the error image, which is a 200.
 */
static void
test_watermark_overlay_without_slash(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4("watermark/0.2,0.5,se", url, "overlay=abc", "overlay");
    dims_response *response = dims_get(path);

    CHECK(response->transport_error == NULL,
          "the worker must answer, not die: %s",
          response->transport_error ? response->transport_error : "");
    CHECK(response->status >= 400 && response->status < 500,
          "a malformed overlay is a client error, got %ld", response->status);

    dims_response_free(response);
    free(path);
    free(url);
}

/* The server with no error image, so a refusal reports its own status. */
static const char *
no_error_image_url(void)
{
    const char *from_env = getenv("DIMS_TEST_NO_ERROR_IMAGE_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8001";
}

/* The server that sets DimsAllowlistSigned enforce. */
static const char *
enforced_url(void)
{
    const char *from_env = getenv("DIMS_TEST_ALLOWLIST_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8003";
}

/* An unsigned /dims3/ watermark that names an arbitrary overlay URL. */
static char *
dims3_watermark_path(const char *overlay_url)
{
    char *url = dims_fixture_url("grid.png");
    char *enc_url = dims_urlencode(url);
    char *enc_overlay = dims_urlencode(overlay_url);
    size_t len = strlen(enc_url) + strlen(enc_overlay) + 128;
    char *path = malloc(len);

    snprintf(path, len, "/dims3/%s/watermark/1.0,0.5,se/?url=%s&overlay=%s",
             DIMS_TEST_CLIENT, enc_url, enc_overlay);

    free(enc_overlay);
    free(enc_url);
    free(url);

    return path;
}

/*
 * The overlay follows the same allowlist rule as the source. On an unsigned
 * request the allowlist is enforced, so an overlay off the allowlist is
 * refused. The source stays on the allowlist, so only the overlay is at issue.
 * The no-error-image server reports the refusal as its own status.
 */
static void
test_watermark_overlay_off_allowlist_is_refused(void)
{
    char base[2048];
    char *allowed = dims_fixture_url("overlay.png");
    char *off_path = dims3_watermark_path("http://notallowed:8080/overlay.png");
    char *on_path = dims3_watermark_path(allowed);
    dims_response *off;
    dims_response *on;

    snprintf(base, sizeof(base), "%s%s", no_error_image_url(), off_path);
    off = dims_get_absolute(base);
    CHECK(off->transport_error == NULL, "the worker must answer: %s",
          off->transport_error ? off->transport_error : "");
    CHECK(off->status >= 400,
          "an overlay off the allowlist must be refused, got %ld", off->status);

    snprintf(base, sizeof(base), "%s%s", no_error_image_url(), on_path);
    on = dims_get_absolute(base);
    CHECK_INT(on->status, 200, "an overlay on the allowlist");

    dims_response_free(off);
    dims_response_free(on);
    free(off_path);
    free(on_path);
    free(allowed);
}

/*
 * A cached overlay is validated on the way out, not only on the way in. One
 * server writes the entry, and a server that enforces the allowlist refuses
 * the same entry rather than serving it from disk.
 *
 * The cache is shared by every virtual host in the process and keyed on the
 * URL, so without the check a permissive host could seed what an enforcing
 * host serves.
 */
static void
test_watermark_cached_overlay_is_revalidated(void)
{
    char *url = dims_fixture_url("grid.png");
    char *overlay = dims_urlencode("http://notallowed:8080/overlay.png");
    char extra[1024];
    char *path;
    char full[2048];
    dims_response *primed;
    dims_response *enforced;

    snprintf(extra, sizeof(extra), "overlay=%s", overlay);
    /* A signed request under the default log mode fetches and caches it. */
    path = dims_sign_dims4("watermark/1.0,0.5,se", url, extra, "overlay");

    primed = dims_get(path);
    CHECK_INT(primed->status, 200, "a signed off-allowlist overlay is cached under log");

    /* The same signed request on the enforcing server must not serve the
     * cached entry. It answers with the error image instead. */
    snprintf(full, sizeof(full), "%s%s", enforced_url(), path);
    enforced = dims_get_absolute(full);
    CHECK(enforced->transport_error == NULL, "the worker must answer: %s",
          enforced->transport_error ? enforced->transport_error : "");
    CHECK(enforced->body_len != primed->body_len,
          "the enforcing server must not serve the cached composite: "
          "primed %zu bytes, enforced %zu bytes",
          primed->body_len, enforced->body_len);

    dims_response_free(primed);
    dims_response_free(enforced);
    free(path);
    free(overlay);
    free(url);
}

/*
 * The overlay is scaled to a fraction of the larger side of the source, so a
 * source of one pixel scales it to less than a pixel. No image has a side of
 * none, so the overlay keeps one and the request is answered.
 */
static void
test_watermark_on_a_one_pixel_source(void)
{
    char *url = dims_fixture_url("grid.png");
    char *overlay = dims_fixture_url("overlay.png");
    char *encoded = dims_urlencode(overlay);
    char extra[1024];
    char *path;
    dims_response *response;

    snprintf(extra, sizeof(extra), "overlay=%s", encoded);
    path = dims_sign_dims4("resize/1x1!/watermark/0.2,0.8,ne", url, extra, "overlay");
    response = dims_get(path);

    CHECK_INT(response->status, 200, "a watermark on a one pixel source");

    dims_response_free(response);
    free(path);
    free(encoded);
    free(overlay);
    free(url);
}

const dims_test dims_tests_watermark[] = {

    { "TestWatermark", test_watermark, NULL },
    { "TestWatermarkShortArgumentsAreStable",
      test_watermark_short_arguments_are_stable, NULL },
    { "TestWatermarkOverlayWithoutSlash", test_watermark_overlay_without_slash,
      "a failed operation answers 200 with the error image" },
    { "TestWatermarkOverlayOffAllowlistIsRefused",
      test_watermark_overlay_off_allowlist_is_refused, NULL },
    { "TestWatermarkCachedOverlayIsRevalidated",
      test_watermark_cached_overlay_is_revalidated, NULL },
    { "TestWatermarkOnAOnePixelSource",
      test_watermark_on_a_one_pixel_source, NULL },
    DIMS_TEST_END
};
