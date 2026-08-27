/*
 * Ported from ../go-dims/internal/commands/crop_test.go.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "../lib/common.h"

static void
test_crop(void)
{
    dims_run_golden("TestCrop", "grid.png", "crop/256x256+256+0", 256, 256);
}

static void
test_crop_percent(void)
{
    dims_run_golden("TestCropPercent", "grid.png", "crop/50%x50%+50%+0", -1, -1);
}

static void
test_crop_percent_with_absolute(void)
{
    dims_run_golden("TestCropPercentWithAbsolute", "grid.png", "crop/50%x50%+50%+256",
                    -1, -1);
}

/* The requested region runs past the bottom edge, so the result is clipped. */
static void
test_crop_region_larger_than_image(void)
{
    dims_run_golden("TestCropRegionLargerThanImage", "grid.png", "crop/512x512+0+256",
                    -1, -1);
}

static void
test_crop_x_offset_outside_image(void)
{
    dims_run_golden("TestCropXOffsetOutsideImage", "grid.png", "crop/256x256+768+768",
                    -1, -1);
}

static void
test_crop_y_offset_outside_image(void)
{
    dims_run_golden("TestCropYOffsetOutsideImage", "grid.png", "crop/256x256+0+768",
                    -1, -1);
}

const dims_test dims_tests_crop[] = {
    { "TestCrop", test_crop, NULL },
    { "TestCropPercent", test_crop_percent, NULL },
    { "TestCropPercentWithAbsolute", test_crop_percent_with_absolute, NULL },
    { "TestCropRegionLargerThanImage", test_crop_region_larger_than_image, NULL },
    { "TestCropXOffsetOutsideImage", test_crop_x_offset_outside_image, NULL },
    { "TestCropYOffsetOutsideImage", test_crop_y_offset_outside_image, NULL },
    DIMS_TEST_END
};
