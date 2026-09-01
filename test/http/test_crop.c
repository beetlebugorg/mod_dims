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

/*
 * A region entirely outside the image has nothing to cut out, so the command
 * is refused and this server answers with its error image. The status the
 * refusal carries is on the server that has no error image, in
 * test_no_error_image.c.
 */
static void
assert_refused(const char *commands, const char *what)
{
    dims_response *refused = dims_request_ops(commands, "grid.png");
    dims_image_size size;

    if (refused == NULL) {
        return;
    }

    /* The error image is the source at its full size, so a refusal answers
     * 512 by 512 where the crop would have given the region it names. */
    size = dims_must_size(refused->body, refused->body_len);

    CHECK(size.width == 512 && size.height == 512,
          "%s must be refused", what);

    dims_response_free(refused);
}

static void
test_crop_x_offset_outside_image(void)
{
    assert_refused("crop/256x256+768+768", "an x offset past the image");
}

static void
test_crop_y_offset_outside_image(void)
{
    assert_refused("crop/256x256+0+768", "a y offset past the image");
}

/*
 * An offset of exactly the width leaves a region no pixels wide. The offsets
 * on either side of it are accepted, so only this one value used to end the
 * request with 500.
 *
 * Not a port. go-dims covers the offsets further out, not the one on the edge.
 */
static void
test_crop_offset_on_the_edge(void)
{
    assert_refused("crop/50x50+512+0", "an x offset of exactly the width");

    /* One column remains, so the crop keeps a strip one pixel wide. */
    dims_run_golden("TestCropOffsetOnTheEdge", "grid.png", "crop/50x50+511+0",
                    1, 50);
}

const dims_test dims_tests_crop[] = {
    { "TestCrop", test_crop, NULL },
    { "TestCropPercent", test_crop_percent, NULL },
    { "TestCropPercentWithAbsolute", test_crop_percent_with_absolute, NULL },
    { "TestCropRegionLargerThanImage", test_crop_region_larger_than_image, NULL },
    { "TestCropXOffsetOutsideImage", test_crop_x_offset_outside_image, NULL },
    { "TestCropYOffsetOutsideImage", test_crop_y_offset_outside_image, NULL },
    { "TestCropOffsetOnTheEdge", test_crop_offset_on_the_edge, NULL },
    DIMS_TEST_END
};
