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

/*
 * A region entirely outside the image has nothing to cut out, so the command
 * is refused. go-dims answers the same two arguments with an error, and a
 * request that carries them gets 400 from either project.
 */
static void
TestCropXOffsetOutsideImage_case(void)
{
    CHECK_INT(dims_operation_status("grid.png", dims_crop_operation,
                                    "256x256+768+768"),
              DIMS_BAD_ARGUMENTS, "an x offset past the image");
}

static void
TestCropYOffsetOutsideImage_case(void)
{
    CHECK_INT(dims_operation_status("grid.png", dims_crop_operation,
                                    "256x256+0+768"),
              DIMS_BAD_ARGUMENTS, "a y offset past the image");
}

/*
 * An offset of exactly the width leaves a region no pixels wide. ImageMagick
 * refuses that crop, and the offsets on either side of it are accepted, so
 * only this one value used to end the request with 500.
 *
 * This case and the one below it are not ports. go-dims covers the offsets
 * further out, not the one on the edge.
 */
static void
TestCropOffsetOnTheEdge_case(void)
{
    CHECK_INT(dims_operation_status("grid.png", dims_crop_operation,
                                    "50x50+512+0"),
              DIMS_BAD_ARGUMENTS, "an x offset of exactly the width");
    CHECK_INT(dims_operation_status("grid.png", dims_crop_operation,
                                    "50x50+0+512"),
              DIMS_BAD_ARGUMENTS, "a y offset of exactly the height");

    /* One column remains at the offset before it, so that one is a crop. */
    CHECK_INT(dims_operation_status("grid.png", dims_crop_operation,
                                    "50x50+511+0"),
              DIMS_SUCCESS, "one pixel inside the edge");
}

/*
 * A width or a height of zero means the rest of the image, which ImageMagick
 * fills in. Neither empties the region.
 */
static void
TestCropWithoutHeight_case(void)
{
    dims_run_operation("TestCropWithoutHeight", "grid.png", dims_crop_operation,
                       "256x+0+0", 256, 512);
}

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
    { "TestCropOffsetOnTheEdge", TestCropOffsetOnTheEdge_case, NULL },
    { "TestCropWithoutHeight", TestCropWithoutHeight_case, NULL },
    { "TestCropAcceptsSpacesForPlus", test_crop_accepts_spaces_for_plus, NULL },
    DIMS_TEST_END
};
