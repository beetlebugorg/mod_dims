/*
 * Ported from ../go-dims/internal/commands/crop_test.go.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "operation.h"

#define CROP(name, args, w, h)                                            \
    static void name##_case(void)                                         \
    {                                                                     \
        dims_run_operation(#name, "grid.png", dims_crop_operation, args,  \
                           (w), (h));                                     \
    }

CROP(TestCrop, "256x256+256+0", 256, 256)
CROP(TestCropPercent, "50%x50%+50%+0", 256, 256)
CROP(TestCropPercentWithAbsolute, "50%x50%+50%+256", 256, 256)
CROP(TestCropRegionLargerThanImage, "512x512+0+256", 512, 256)

/* A region entirely outside the image collapses to one pixel rather than
 * failing. Recorded, not endorsed. */
CROP(TestCropXOffsetOutsideImage, "256x256+768+768", 1, 1)
CROP(TestCropYOffsetOutsideImage, "256x256+0+768", 1, 1)

/*
 * The command replaces a space with a plus before parsing, because some user
 * agents escape the plus as %20. See src/mod_dims_ops.c:207-218.
 */
static void
test_crop_accepts_spaces_for_plus(void)
{
    dims_run_operation("TestCropAcceptsSpacesForPlus", "grid.png",
                       dims_crop_operation, "256x256 256 0", 256, 256);
}

const dims_test dims_tests_unit_crop[] = {
    { "TestCrop", TestCrop_case, NULL },
    { "TestCropPercent", TestCropPercent_case, NULL },
    { "TestCropPercentWithAbsolute", TestCropPercentWithAbsolute_case, NULL },
    { "TestCropRegionLargerThanImage", TestCropRegionLargerThanImage_case, NULL },
    { "TestCropXOffsetOutsideImage", TestCropXOffsetOutsideImage_case, NULL },
    { "TestCropYOffsetOutsideImage", TestCropYOffsetOutsideImage_case, NULL },
    { "TestCropAcceptsSpacesForPlus", test_crop_accepts_spaces_for_plus, NULL },
    DIMS_TEST_END
};
