/*
 * Ported from ../go-dims/internal/commands/rotate_test.go, plus flipflop,
 * which go-dims does not test under that name.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "operation.h"

#define ROTATE(name, args, w, h)                                             \
    static void name##_case(void)                                            \
    {                                                                        \
        dims_run_operation(#name, "grid.png", dims_rotate_operation, args,   \
                           (w), (h));                                        \
    }

ROTATE(TestRotate45, "45", -1, -1)
ROTATE(TestRotate90, "90", 512, 512)
ROTATE(TestRotate180, "180", 512, 512)
ROTATE(TestRotate270, "270", 512, 512)

/* A non-square source proves the axes actually swap. */
static void
test_rotate_90_swaps_axes(void)
{
    dims_run_operation("TestRotate90SwapsAxes", "portrait.jpg",
                       dims_rotate_operation, "90", 512, 256);
}

static void
test_flip_horizontal(void)
{
    dims_run_operation("TestFlipHorizontal", "grid.png", dims_flipflop_operation,
                       "horizontal", 512, 512);
}

static void
test_flip_vertical(void)
{
    dims_run_operation("TestFlipVertical", "grid.png", dims_flipflop_operation,
                       "vertical", 512, 512);
}

const dims_test dims_tests_unit_rotate[] = {
    { "TestRotate45", TestRotate45_case, NULL },
    { "TestRotate90", TestRotate90_case, NULL },
    { "TestRotate180", TestRotate180_case, NULL },
    { "TestRotate270", TestRotate270_case, NULL },
    { "TestRotate90SwapsAxes", test_rotate_90_swaps_axes, NULL },
    { "TestFlipHorizontal", test_flip_horizontal, NULL },
    { "TestFlipVertical", test_flip_vertical, NULL },
    DIMS_TEST_END
};
