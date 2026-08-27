/*
 * Ported from ../go-dims/internal/commands/resize_test.go.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "operation.h"

#define RESIZE(name, args, w, h)                                            \
    static void name##_case(void)                                           \
    {                                                                       \
        dims_run_operation(#name, "grid.png", dims_resize_operation, args,  \
                           (w), (h));                                       \
    }

RESIZE(TestResize, "256x256", 256, 256)
RESIZE(TestResizeOnlySmaller, "256x256<", 512, 512)
RESIZE(TestResizeOnlyLarger, "256x256>", 256, 256)
RESIZE(TestResizeMaintainAspectRatio, "100x50", 50, 50)
RESIZE(TestResizeIgnoreAspectRatio, "100x50!", 100, 50)
RESIZE(TestResizeIgnoreAspectRatioWidthOnly, "100x!", 100, -1)
RESIZE(TestResizeFill, "50x100^", 100, 100)

/* A geometry the parser cannot read must be refused, not applied. */
static void
test_resize_rejects_bad_geometry(void)
{
    apr_status_t code = dims_operation_status("grid.png", dims_resize_operation,
                                              "not-a-size");

    CHECK(code != DIMS_SUCCESS, "an unparsable geometry must not succeed");
}

const dims_test dims_tests_unit_resize[] = {
    { "TestResize", TestResize_case, NULL },
    { "TestResizeOnlySmaller", TestResizeOnlySmaller_case, NULL },
    { "TestResizeOnlyLarger", TestResizeOnlyLarger_case, NULL },
    { "TestResizeMaintainAspectRatio", TestResizeMaintainAspectRatio_case, NULL },
    { "TestResizeIgnoreAspectRatio", TestResizeIgnoreAspectRatio_case, NULL },
    { "TestResizeIgnoreAspectRatioWidthOnly", TestResizeIgnoreAspectRatioWidthOnly_case, NULL },
    { "TestResizeFill", TestResizeFill_case, NULL },
    { "TestResizeRejectsBadGeometry", test_resize_rejects_bad_geometry, NULL },
    DIMS_TEST_END
};
