/*
 * format, quality, and strip. mod_dims operations with no direct go-dims
 * case.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

static void
test_format_jpeg(void)
{
    dims_run_golden("TestFormatJpeg", "grid.png", "format/jpg", 512, 512);
}

static void
test_format_gif(void)
{
    dims_run_golden("TestFormatGif", "grid.png", "format/gif", 512, 512);
}

static void
test_format_webp(void)
{
    dims_run_golden("TestFormatWebp", "grid.png", "format/webp", 512, 512);
}

static void
test_quality(void)
{
    dims_run_golden("TestQuality", "pexels-photo-1539116.jpeg", "quality/25", 512, 640);
}

/*
 * quality is parsed with base 0, so a leading zero is read as octal. 070
 * becomes 56. Finding M8.
 */
static void
test_quality_leading_zero(void)
{
    dims_response *a = dims_request_ops("quality/070", "pexels-photo-1539116.jpeg");
    dims_response *b = dims_request_ops("quality/56", "pexels-photo-1539116.jpeg");

    CHECK_INT(a->status, 200, "quality/070");
    CHECK_INT(b->status, 200, "quality/56");
    CHECK(a->body_len == b->body_len,
          "quality/070 is read as octal 56: want %zu bytes, got %zu",
          b->body_len, a->body_len);

    dims_response_free(a);
    dims_response_free(b);
}

static void
test_strip_true(void)
{
    dims_run_golden("TestStripTrue", "pexels-photo-1539116.jpeg", "strip/true", 512, 640);
}

static void
test_strip_false(void)
{
    dims_run_golden("TestStripFalse", "pexels-photo-1539116.jpeg", "strip/false", 512, 640);
}

/*
 * strip runs even when the request does not name it. See
 * src/mod_dims.c:1289-1305.
 */
static void
test_strip_runs_by_default(void)
{
    dims_response *implicit = dims_request_ops("resize/256x256",
                                               "pexels-photo-1539116.jpeg");
    dims_response *explicit_strip = dims_request_ops("resize/256x256/strip/true",
                                                     "pexels-photo-1539116.jpeg");

    CHECK_INT(implicit->status, 200, "resize without strip");
    CHECK_INT(explicit_strip->status, 200, "resize with strip");
    CHECK(implicit->body_len == explicit_strip->body_len,
          "strip is the default: want %zu bytes, got %zu",
          explicit_strip->body_len, implicit->body_len);

    dims_response_free(implicit);
    dims_response_free(explicit_strip);
}

const dims_test dims_tests_output[] = {
    { "TestFormatJpeg", test_format_jpeg, NULL },
    { "TestFormatGif", test_format_gif, NULL },
    { "TestFormatWebp", test_format_webp, NULL },
    { "TestQuality", test_quality, NULL },
    { "TestQualityLeadingZero", test_quality_leading_zero, NULL },
    { "TestStripTrue", test_strip_true, NULL },
    { "TestStripFalse", test_strip_false, NULL },
    { "TestStripRunsByDefault", test_strip_runs_by_default, NULL },
    DIMS_TEST_END
};
