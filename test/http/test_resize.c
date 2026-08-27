/*
 * Ported from ../go-dims/internal/commands/resize_test.go.
 *
 * The go-dims cases are MIT licensed. See NOTICE.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "../lib/common.h"

static void
test_resize(void)
{
    dims_run_golden("TestResize", "grid.png", "resize/256x256", 256, 256);
}

/* ImageMagick reads '<' as "enlarge only if smaller". grid.png is 512x512 and
 * the target is smaller, so nothing changes. */
static void
test_resize_only_smaller(void)
{
    dims_run_golden("TestResizeOnlySmaller", "grid.png", "resize/256x256<", 512, 512);
}

static void
test_resize_only_larger(void)
{
    dims_run_golden("TestResizeOnlyLarger", "grid.png", "resize/256x256>", 256, 256);
}

/* 100x50 keeps the aspect ratio, so a square source lands on 50x50. */
static void
test_resize_maintain_aspect_ratio(void)
{
    dims_run_golden("TestResizeMaintainAspectRatio", "grid.png", "resize/100x50", 50, 50);
}

static void
test_resize_ignore_aspect_ratio(void)
{
    dims_run_golden("TestResizeIgnoreAspectRatio", "grid.png", "resize/100x50!", 100, 50);
}

static void
test_resize_ignore_aspect_ratio_width_only(void)
{
    dims_run_golden("TestResizeIgnoreAspectRatioWidthOnly", "grid.png", "resize/100x!",
                    100, -1);
}

static void
test_resize_fill(void)
{
    dims_run_golden("TestResizeFill", "grid.png", "resize/50x100^", -1, -1);
}

static void
test_resize_fill_with_crop(void)
{
    dims_run_golden("TestResizeFillWithCrop", "grid.png", "resize/50x100^/crop/50x100",
                    50, 100);
}

const dims_test dims_tests_resize[] = {
    { "TestResize", test_resize, NULL },
    { "TestResizeOnlySmaller", test_resize_only_smaller, NULL },
    { "TestResizeOnlyLarger", test_resize_only_larger, NULL },
    { "TestResizeMaintainAspectRatio", test_resize_maintain_aspect_ratio, NULL },
    { "TestResizeIgnoreAspectRatio", test_resize_ignore_aspect_ratio, NULL },
    { "TestResizeIgnoreAspectRatioWidthOnly", test_resize_ignore_aspect_ratio_width_only, NULL },
    { "TestResizeFill", test_resize_fill, NULL },
    { "TestResizeFillWithCrop", test_resize_fill_with_crop, NULL },
    DIMS_TEST_END
};
