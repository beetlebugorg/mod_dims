/*
 * Ported from ../go-dims/internal/commands/thumbnail_test.go.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "../lib/common.h"

static void
test_thumbnail(void)
{
    dims_run_golden("TestThumbnail", "grid.png", "thumbnail/256x256", 256, 256);
}

static void
test_thumbnail_with_crop(void)
{
    dims_run_golden("TestThumbnailWithCrop", "grid.png", "thumbnail/256x128", 256, 128);
}

static void
test_thumbnail_without_height(void)
{
    dims_run_golden("TestThumbnailWithoutHeight", "pexels-photo-1539116.jpeg",
                    "thumbnail/32x", -1, -1);
}

static void
test_thumbnail_ignore_aspect_ratio(void)
{
    dims_run_golden("TestThumbnailIgnoreAspectRatio", "grid.png", "thumbnail/256x128!",
                    -1, -1);
}

static void
test_legacy_thumbnail(void)
{
    dims_run_golden("TestLegacyThumbnail", "grid.png", "legacy_thumbnail/256x128",
                    256, 128);
}

static void
test_legacy_thumbnail_without_height(void)
{
    dims_run_golden("TestLegacyThumbnailWithoutHeight", "pexels-photo-1539116.jpeg",
                    "legacy_thumbnail/32x", -1, -1);
}

/* mod_dims only. go-dims has no legacy_crop. */
static void
test_legacy_crop(void)
{
    dims_run_golden("TestLegacyCrop", "grid.png", "legacy_crop/256x128", -1, -1);
}

const dims_test dims_tests_thumbnail[] = {
    { "TestThumbnail", test_thumbnail, NULL },
    { "TestThumbnailWithCrop", test_thumbnail_with_crop, NULL },
    { "TestThumbnailWithoutHeight", test_thumbnail_without_height, NULL },
    { "TestThumbnailIgnoreAspectRatio", test_thumbnail_ignore_aspect_ratio, NULL },
    { "TestLegacyThumbnail", test_legacy_thumbnail, NULL },
    { "TestLegacyThumbnailWithoutHeight", test_legacy_thumbnail_without_height, NULL },
    { "TestLegacyCrop", test_legacy_crop, NULL },
    DIMS_TEST_END
};
