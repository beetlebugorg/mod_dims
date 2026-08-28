/*
 * format, quality, and strip.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operation.h"

#include <string.h>

static void
test_format_jpeg(void)
{
    dims_run_operation("TestFormatJpeg", "grid.png", dims_format_operation, "jpg",
                       512, 512);
}

static void
test_format_gif(void)
{
    dims_run_operation("TestFormatGif", "grid.png", dims_format_operation, "gif",
                       512, 512);
}

static void
test_format_webp(void)
{
    dims_run_operation("TestFormatWebp", "grid.png", dims_format_operation, "webp",
                       512, 512);
}

/* An unknown format must be refused, not silently ignored. */
static void
test_format_rejects_unknown(void)
{
    apr_status_t code = dims_operation_status("grid.png", dims_format_operation,
                                              "not-a-format");

    CHECK(code != DIMS_SUCCESS, "an unknown format must not succeed");
}

static void
test_quality(void)
{
    dims_run_operation("TestQuality", "pexels-photo-1539116.jpeg",
                       dims_quality_operation, "25", 512, 640);
}

/*
 * quality parses with base 0, so a leading zero is read as octal.
 * 070 becomes 56. The two calls below must agree once the value is parsed as
 * decimal, and they disagree today.
 */
static void
test_quality_leading_zero(void)
{
    dims_request_rec *octal = dims_fixture_request("pexels-photo-1539116.jpeg", NULL);
    dims_request_rec *decimal = dims_fixture_request("pexels-photo-1539116.jpeg", NULL);
    const char *error = NULL;

    dims_quality_operation(octal, apr_pstrdup(octal->pool, "070"), &error);
    dims_quality_operation(decimal, apr_pstrdup(decimal->pool, "70"), &error);

    CHECK_INT(MagickGetImageCompressionQuality(octal->wand),
              MagickGetImageCompressionQuality(decimal->wand),
              "quality/070 must mean 70, not octal 56");

    dims_fixture_free(octal);
    dims_fixture_free(decimal);
}

/*
 * Nothing checks that the value is between 1 and 100.
 */
static void
test_quality_out_of_range(void)
{
    apr_status_t code = dims_operation_status("pexels-photo-1539116.jpeg",
                                              dims_quality_operation, "500");

    CHECK(code != DIMS_SUCCESS, "quality/500 must be refused");
}

/*
 * quality only lowers. A request for a higher value than the image already
 * carries is ignored. See src/mod_dims_ops.c:243-250.
 */
static void
test_quality_only_lowers(void)
{
    dims_request_rec *d = dims_fixture_request("pexels-photo-1539116.jpeg", NULL);
    size_t before = MagickGetImageCompressionQuality(d->wand);
    const char *error = NULL;

    dims_quality_operation(d, apr_pstrdup(d->pool, "100"), &error);

    CHECK_INT(MagickGetImageCompressionQuality(d->wand), before,
              "quality must not raise the existing value");

    dims_fixture_free(d);
}

static void
test_strip_true(void)
{
    dims_run_operation("TestStripTrue", "pexels-photo-1539116.jpeg",
                       dims_strip_operation, "true", 512, 640);
}

static void
test_strip_false(void)
{
    dims_run_operation("TestStripFalse", "pexels-photo-1539116.jpeg",
                       dims_strip_operation, "false", 512, 640);
}

/*
 * A NULL argument is what dims_process_image passes when the request does not
 * name strip. The image is stripped anyway, because the configuration default
 * is on. See src/mod_dims_ops.c:75-90.
 */
static void
test_strip_null_follows_config(void)
{
    dims_run_operation("TestStripNullFollowsConfig", "pexels-photo-1539116.jpeg",
                       dims_strip_operation, NULL, 512, 640);
}

const dims_test dims_tests_unit_output[] = {
    { "TestFormatJpeg", test_format_jpeg, NULL },
    { "TestFormatGif", test_format_gif, NULL },
    { "TestFormatWebp", test_format_webp, NULL },
    { "TestFormatRejectsUnknown", test_format_rejects_unknown, NULL },
    { "TestQuality", test_quality, NULL },
    { "TestQualityLeadingZero", test_quality_leading_zero,
      "quality parses with base 0" },
    { "TestQualityOutOfRange", test_quality_out_of_range,
      "quality is not range checked" },
    { "TestQualityOnlyLowers", test_quality_only_lowers, NULL },
    { "TestStripTrue", test_strip_true, NULL },
    { "TestStripFalse", test_strip_false, NULL },
    { "TestStripNullFollowsConfig", test_strip_null_follows_config, NULL },
    DIMS_TEST_END
};
