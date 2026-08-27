/*
 * Ported from ../go-dims/internal/commands/rotate_test.go.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "../lib/common.h"

static void
test_rotate_45(void)
{
    dims_run_golden("TestRotate45", "grid.png", "rotate/45", -1, -1);
}

static void
test_rotate_90(void)
{
    dims_run_golden("TestRotate90", "grid.png", "rotate/90", 512, 512);
}

static void
test_rotate_180(void)
{
    dims_run_golden("TestRotate180", "grid.png", "rotate/180", 512, 512);
}

static void
test_rotate_270(void)
{
    dims_run_golden("TestRotate270", "grid.png", "rotate/270", 512, 512);
}

/* mod_dims only. flipflop has no go-dims equivalent under that name. */
static void
test_flip_horizontal(void)
{
    dims_run_golden("TestFlipHorizontal", "grid.png", "flipflop/horizontal", 512, 512);
}

static void
test_flip_vertical(void)
{
    dims_run_golden("TestFlipVertical", "grid.png", "flipflop/vertical", 512, 512);
}

const dims_test dims_tests_rotate[] = {
    { "TestRotate45", test_rotate_45, NULL },
    { "TestRotate90", test_rotate_90, NULL },
    { "TestRotate180", test_rotate_180, NULL },
    { "TestRotate270", test_rotate_270, NULL },
    { "TestFlipHorizontal", test_flip_horizontal, NULL },
    { "TestFlipVertical", test_flip_vertical, NULL },
    DIMS_TEST_END
};
