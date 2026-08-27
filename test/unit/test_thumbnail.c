/*
 * Ported from ../go-dims/internal/commands/thumbnail_test.go.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "operation.h"

static void
test_thumbnail(void)
{
    dims_run_operation("TestThumbnail", "grid.png", dims_thumbnail_operation,
                       "256x256", 256, 256);
}

static void
test_thumbnail_with_crop(void)
{
    dims_run_operation("TestThumbnailWithCrop", "grid.png", dims_thumbnail_operation,
                       "256x128", 256, 128);
}

static void
test_thumbnail_without_height(void)
{
    dims_run_operation("TestThumbnailWithoutHeight", "pexels-photo-1539116.jpeg",
                       dims_thumbnail_operation, "32x", 32, 40);
}

static void
test_thumbnail_ignore_aspect_ratio(void)
{
    dims_run_operation("TestThumbnailIgnoreAspectRatio", "grid.png",
                       dims_thumbnail_operation, "256x128!", 256, 128);
}

static void
test_legacy_thumbnail(void)
{
    dims_run_operation("TestLegacyThumbnail", "grid.png",
                       dims_legacy_thumbnail_operation, "256x128", 256, 128);
}

static void
test_legacy_thumbnail_without_height(void)
{
    dims_run_operation("TestLegacyThumbnailWithoutHeight", "pexels-photo-1539116.jpeg",
                       dims_legacy_thumbnail_operation, "32x", 32, 20);
}

/*
 * legacy_thumbnail picks its resampler from the requested size: under 200 in
 * both dimensions it uses MagickThumbnailImage, and at or above that it uses
 * MagickScaleImage. See src/mod_dims_ops.c:596-601. The two produce different
 * bytes, so both arms need a case.
 */
static void
test_legacy_thumbnail_small(void)
{
    dims_run_operation("TestLegacyThumbnailSmall", "grid.png",
                       dims_legacy_thumbnail_operation, "100x100", 100, 100);
}

static void
test_legacy_crop(void)
{
    dims_run_operation("TestLegacyCrop", "grid.png", dims_legacy_crop_operation,
                       "256x128", 256, 128);
}

const dims_test dims_tests_unit_thumbnail[] = {
    { "TestThumbnail", test_thumbnail, NULL },
    { "TestThumbnailWithCrop", test_thumbnail_with_crop, NULL },
    { "TestThumbnailWithoutHeight", test_thumbnail_without_height, NULL },
    { "TestThumbnailIgnoreAspectRatio", test_thumbnail_ignore_aspect_ratio, NULL },
    { "TestLegacyThumbnail", test_legacy_thumbnail, NULL },
    { "TestLegacyThumbnailWithoutHeight", test_legacy_thumbnail_without_height, NULL },
    { "TestLegacyThumbnailSmall", test_legacy_thumbnail_small, NULL },
    { "TestLegacyCrop", test_legacy_crop, NULL },
    DIMS_TEST_END
};
