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
 * Finding C5, the crash half. strrchr returns NULL when the overlay carries no
 * slash, and the next line dereferences it. See src/mod_dims_ops.c:378.
 *
 * The case runs the operation directly, so a crash takes the test binary down
 * and names itself. Over HTTP the same defect only shows as a dead worker.
 * PR 13 checks the pointer.
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

/*
 * Finding M9. opacity, size, and gravity are read whether or not their token
 * was present. A watermark with one argument of three leaves two of them
 * holding whatever the stack held.
 *
 * The operation does fail today, but only because the garbage width and
 * height make MagickScaleImage fail. That is an accident, not validation, and
 * an accident is not a property worth asserting. What this case pins is the
 * property M9 actually threatens: the same request must produce the same
 * outcome every time.
 *
 * PR 30 initializes the three and refuses the wrong argument count
 * deliberately. This case then becomes a check that the refusal is stable,
 * which it still is.
 */
static void
test_watermark_short_arguments(void)
{
    apr_status_t first = dims_operation_status_with_query(
        "grid.png", dims_watermark_operation, "0.2", OVERLAY);
    apr_status_t second = dims_operation_status_with_query(
        "grid.png", dims_watermark_operation, "0.2", OVERLAY);
    apr_status_t third = dims_operation_status_with_query(
        "grid.png", dims_watermark_operation, "0.2", OVERLAY);

    dims_test_logf("a watermark with one argument returns %d, %d, %d",
                   (int) first, (int) second, (int) third);

    CHECK(first == second && second == third,
          "the same request must return the same status: %d, %d, %d",
          (int) first, (int) second, (int) third);

}
const dims_test dims_tests_unit_watermark[] = {
    { "TestWatermark", test_watermark, NULL },
    { "TestWatermarkNorthWest", test_watermark_north_west, NULL },
    { "TestWatermarkOverlayWithoutSlash", test_watermark_overlay_without_slash, "C5" },
    { "TestWatermarkWithoutOverlay", test_watermark_without_overlay, NULL },
    { "TestWatermarkShortArguments", test_watermark_short_arguments, NULL },
    DIMS_TEST_END
};
