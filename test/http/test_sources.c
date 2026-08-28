/*
 * Source formats: the animated GIF, the SVG, and the CMYK JPEG. Each records
 * a finding that a later pull request changes.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

static const char *
animated_url(void)
{
    const char *from_env = getenv("DIMS_TEST_ANIMATED_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8006";
}

/* The server that runs the commands over every frame. */
static dims_response *
animated_request(const char *commands, const char *fixture)
{
    char *url = dims_fixture_url(fixture);
    char *path = dims_sign_dims4(commands, url, NULL, NULL);
    char full[2048];
    dims_response *response;

    snprintf(full, sizeof(full), "%s%s", animated_url(), path);
    response = dims_get_absolute(full);

    free(path);
    free(url);

    return response;
}

/* Under transform every command runs, and every frame survives. */
static void
test_animated_gif_transformed(void)
{
    dims_response *response = animated_request("resize/100x100", "animated.gif");
    dims_image_size size;

    CHECK_INT(response->status, 200, "an animated GIF under transform");
    size = dims_must_size(response->body, response->body_len);

    dims_test_logf("came back %ldx%ld with %ld frames", size.width, size.height,
                   size.frames);
    CHECK_INT(size.width, 100, "width");
    CHECK_INT(size.height, 100, "height");
    CHECK(size.frames > 1, "every frame must survive, got %ld", size.frames);

    assert_golden("animated.TestAnimatedGifTransformed", response->body,
                  response->body_len, ".gif");
    dims_response_free(response);
}

/* A single frame source is untouched by the directive. */
static void
test_single_frame_under_transform(void)
{
    dims_response *response = animated_request("resize/100x100", "grid.png");
    dims_image_size size;

    CHECK_INT(response->status, 200, "a single frame source under transform");
    size = dims_must_size(response->body, response->body_len);
    CHECK_INT(size.width, 100, "width");

    dims_response_free(response);
}

/*
 * A multi-frame image with no watermark command matches neither
 * arm of the guard at src/mod_dims.c:1197-1290, so every command is skipped
 * and the original comes back at its original size.
 *
 * The golden file records the untransformed original. A second golden follows the
 * fix.
 */
static void
test_animated_gif_ignores_commands(void)
{
    dims_response *response = dims_request_ops("resize/100x100", "animated.gif");
    dims_image_size size;

    CHECK_INT(response->status, 200, "an animated GIF");
    size = dims_must_size(response->body, response->body_len);

    dims_test_logf("animated.gif came back %ldx%ld with %ld frames",
                   size.width, size.height, size.frames);

    CHECK_INT(size.width, 100, "width after resize/100x100");
    CHECK_INT(size.height, 100, "height after resize/100x100");

    dims_response_free(response);
}

/* The bytes today, whatever they are, so a later fix can show what changed. */
static void
test_animated_gif_passthrough(void)
{
    dims_run_golden("TestAnimatedGifPassthrough", "animated.gif", "resize/100x100",
                    -1, -1);
}

/*
 * The SVG branch calls apr_pstrcat on a buffer that is not NUL
 * terminated. See src/mod_dims.c:761-767. The fixture has no XML declaration,
 * which is the branch that runs.
 *
 * The case also asserts the response is not the fallback image. Asserting the
 * dimensions alone does not discriminate: dims_cleanup resizes the fallback to
 * the requested size, so a failed render and a successful one are the same
 * shape.
 */
static void
test_svg_source(void)
{
    dims_response *fallback = dims_request_ops("resize/100x100/format/png",
                                               "missing.png");
    dims_response *rendered = dims_request_ops("resize/100x100/format/png",
                                               "sample.svg");
    dims_image_size size;

    CHECK_INT(rendered->status, 200, "an SVG source");

    size = dims_must_size(rendered->body, rendered->body_len);
    CHECK_INT(size.width, 100, "width");
    CHECK_INT(size.height, 100, "height");

    CHECK(fallback->body_len != rendered->body_len ||
              memcmp(fallback->body, rendered->body, rendered->body_len) != 0,
          "the SVG did not render: the response is the fallback image");

    assert_golden("sample.TestSvgSource", rendered->body, rendered->body_len, ".png");

    dims_response_free(fallback);
    dims_response_free(rendered);
}

static void
test_cmyk_source(void)
{
    dims_run_golden("TestCmykSource", "cmyk.jpg", "resize/100x100", 100, 100);
}

static void
test_portrait_source(void)
{
    dims_run_golden("TestPortraitSource", "portrait.jpg", "thumbnail/100x100", -1, -1);
}

/*
 * Content-Length must describe the body. The review predicted a divergence
 * because the header comes from MagickGetImageLength and the body from
 * MagickGetImagesBlob. The harness measured no divergence on these fixtures,
 * so the finding is downgraded: the fix is still right, because a
 * correct Content-Length uses the length actually written, but it closes a
 * latent defect rather than a reproducible one. These two cases guard the
 * property from here on.
 */
static void
test_content_length_matches_body(void)
{
    dims_response *response = dims_request_ops("resize/100x100", "animated.gif");
    const char *header = dims_header_value(response, "Content-Length");

    CHECK(header != NULL, "the response must have Content-Length");
    CHECK_INT(atol(header), (long) response->body_len, "Content-Length");

    dims_response_free(response);
}

static void
test_content_length_matches_body_png(void)
{
    dims_response *response = dims_request_ops("resize/100x100", "grid.png");
    const char *header = dims_header_value(response, "Content-Length");

    CHECK(header != NULL, "the response must have Content-Length");
    CHECK_INT(atol(header), (long) response->body_len, "Content-Length");

    dims_response_free(response);
}

const dims_test dims_tests_sources[] = {
    { "TestAnimatedGifAppliesCommands", test_animated_gif_ignores_commands,
      "passthrough is the default" },
    { "TestAnimatedGifTransformed", test_animated_gif_transformed, NULL },
    { "TestSingleFrameUnderTransform", test_single_frame_under_transform, NULL },
    { "TestAnimatedGifPassthrough", test_animated_gif_passthrough, NULL },
    { "TestSvgSource", test_svg_source, NULL },
    { "TestCmykSource", test_cmyk_source, NULL },
    { "TestPortraitSource", test_portrait_source, NULL },
    { "TestContentLengthMatchesBody", test_content_length_matches_body, NULL },
    { "TestContentLengthMatchesBodyPng", test_content_length_matches_body_png, NULL },
    DIMS_TEST_END
};
