/*
 * autolevel and brightness are ported from
 * ../go-dims/internal/commands/autolevel_test.go and brightness_test.go.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "operation.h"

static void
test_autolevel(void)
{
    dims_run_operation("TestAutolevel", "grid.png", dims_autolevel_operation,
                       "true", 512, 512);
}

static void
test_brightness(void)
{
    dims_run_operation("TestBrightness", "grid.png", dims_brightness_operation,
                       "10x20", 512, 512);
}

static void
test_grayscale(void)
{
    dims_run_operation("TestGrayscale", "grid.png", dims_grayscale_operation,
                       "true", 512, 512);
}

static void
test_invert(void)
{
    dims_run_operation("TestInvert", "grid.png", dims_invert_operation, "true",
                       512, 512);
}

static void
test_sepia(void)
{
    dims_run_operation("TestSepia", "grid.png", dims_sepia_operation, "0.8",
                       512, 512);
}

static void
test_sharpen(void)
{
    dims_run_operation("TestSharpen", "grid.png", dims_sharpen_operation,
                       "0.0x1.5", 512, 512);
}

/*
 * autolevel, grayscale, and invert act only when the argument is exactly
 * "true". Any other value leaves the image alone. See
 * src/mod_dims_ops.c:275-315. The HTTP layer cannot see the difference
 * between "did nothing" and "did nothing visible", so the check belongs here.
 */
static void
test_adjustments_ignore_other_arguments(void)
{
    dims_run_operation("TestGrayscaleIgnoresFalse", "grid.png",
                       dims_grayscale_operation, "false", 512, 512);
    dims_run_operation("TestInvertIgnoresYes", "grid.png", dims_invert_operation,
                       "yes", 512, 512);
}

const dims_test dims_tests_unit_adjustments[] = {
    { "TestAutolevel", test_autolevel, NULL },
    { "TestBrightness", test_brightness, NULL },
    { "TestGrayscale", test_grayscale, NULL },
    { "TestInvert", test_invert, NULL },
    { "TestSepia", test_sepia, NULL },
    { "TestSharpen", test_sharpen, NULL },
    { "TestAdjustmentsIgnoreOtherArguments", test_adjustments_ignore_other_arguments, NULL },
    DIMS_TEST_END
};
