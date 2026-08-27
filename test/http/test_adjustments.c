/*
 * autolevel and brightness are ported from
 * ../go-dims/internal/commands/autolevel_test.go and brightness_test.go.
 * The rest are mod_dims operations go-dims does not test individually.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "../lib/common.h"

static void
test_autolevel(void)
{
    dims_run_golden("TestAutolevel", "grid.png", "autolevel/true", 512, 512);
}

static void
test_brightness(void)
{
    dims_run_golden("TestBrightness", "grid.png", "brightness/10x20", 512, 512);
}

static void
test_grayscale(void)
{
    dims_run_golden("TestGrayscale", "grid.png", "grayscale/true", 512, 512);
}

static void
test_invert(void)
{
    dims_run_golden("TestInvert", "grid.png", "invert/true", 512, 512);
}

static void
test_sepia(void)
{
    dims_run_golden("TestSepia", "grid.png", "sepia/0.8", 512, 512);
}

static void
test_sharpen(void)
{
    dims_run_golden("TestSharpen", "grid.png", "sharpen/0.0x1.5", 512, 512);
}

const dims_test dims_tests_adjustments[] = {
    { "TestAutolevel", test_autolevel, NULL },
    { "TestBrightness", test_brightness, NULL },
    { "TestGrayscale", test_grayscale, NULL },
    { "TestInvert", test_invert, NULL },
    { "TestSepia", test_sepia, NULL },
    { "TestSharpen", test_sharpen, NULL },
    DIMS_TEST_END
};
