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
 * so a short argument list uses uninitialized memory. Finding M9. The values
 * turn out to be stable across requests, so the defect is not observable from
 * outside; confirming it needs valgrind or -fsanitize=memory, which PR 5 adds
 * to CI. This case guards the property that two identical requests agree.
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
 * Finding C5, the crash half. strrchr returns NULL when the overlay has no
 * slash, and the next line dereferences it. See src/mod_dims_ops.c:378.
 * PR 13 checks the result.
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

const dims_test dims_tests_watermark[] = {
    { "TestWatermark", test_watermark, NULL },
    { "TestWatermarkShortArgumentsAreStable",
      test_watermark_short_arguments_are_stable, NULL },
    { "TestWatermarkOverlayWithoutSlash", test_watermark_overlay_without_slash, "C5" },
    DIMS_TEST_END
};
