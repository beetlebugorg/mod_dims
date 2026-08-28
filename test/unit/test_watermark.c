/*
 * The watermark command.
 *
 * go-dims TestReduceOpacityMaterializes is a libvips lifetime test with no
 * mod_dims equivalent, so these cover the composite and the argument parser
 * instead. The overlay is read from the fixture directory by the stub in
 * stub_httpd.c, so no case reaches the network.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operation.h"
#include "stub_httpd.h"

#define OVERLAY "overlay=http://origin:8080/overlay.png"

static void
test_watermark(void)
{
    dims_run_operation_with_query("TestWatermark", "grid.png",
                                  dims_watermark_operation, "0.2,0.5,se", OVERLAY,
                                  512, 512);
}

static void
test_watermark_north_west(void)
{
    dims_run_operation_with_query("TestWatermarkNorthWest", "grid.png",
                                  dims_watermark_operation, "0.5,0.25,nw", OVERLAY,
                                  512, 512);
}

/*
 * strrchr returns NULL when the overlay has no slash, and the next line
 * dereferences it. See src/mod_dims_ops.c:378.
 *
 * The case runs the operation directly, so a crash takes the test binary down
 * and names itself. Over HTTP the same defect only shows as a dead worker.
 * Checking the pointer.
 */
static void
test_watermark_overlay_without_slash(void)
{
    apr_status_t code = dims_operation_status_with_query(
        "grid.png", dims_watermark_operation, "0.2,0.5,se", "overlay=abc");

    CHECK(code != DIMS_SUCCESS, "an overlay with no slash must be refused");
}

/*
 * A missing overlay parameter is refused. This is the one malformed case the
 * command already handles.
 */
static void
test_watermark_without_overlay(void)
{
    apr_status_t code = dims_operation_status_with_query(
        "grid.png", dims_watermark_operation, "0.2,0.5,se", NULL);

    CHECK(code != DIMS_SUCCESS, "a missing overlay must be refused");
}

/* A watermark needs an opacity, a size, and a gravity. */
static void
test_watermark_short_arguments(void)
{
    static const char *const short_lists[] = { "", "0.2", "0.2,0.5", NULL };
    int i;

    for (i = 0; short_lists[i] != NULL; i++) {
        apr_status_t code = dims_operation_status_with_query(
            "grid.png", dims_watermark_operation, short_lists[i], OVERLAY);

        CHECK(code == DIMS_BAD_ARGUMENTS, "watermark with \"%s\" must be "
              "refused, got %d", short_lists[i], (int) code);
    }

    CHECK_INT(dims_operation_status_with_query("grid.png",
                  dims_watermark_operation, "0.2,0.5,zz", OVERLAY),
              DIMS_BAD_ARGUMENTS, "an unknown gravity");
}

const dims_test dims_tests_unit_watermark[] = {
    { "TestWatermark", test_watermark, NULL },
    { "TestWatermarkNorthWest", test_watermark_north_west, NULL },
    { "TestWatermarkOverlayWithoutSlash", test_watermark_overlay_without_slash, NULL },
    { "TestWatermarkWithoutOverlay", test_watermark_without_overlay, NULL },
    { "TestWatermarkShortArguments", test_watermark_short_arguments, NULL },
    DIMS_TEST_END
};
