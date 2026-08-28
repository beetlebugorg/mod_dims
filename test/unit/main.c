/*
 * The in-process entry point. Every case calls an operation in
 * src/mod_dims_ops.c directly, with no httpd and no network.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fixture.h"
#include "stub_httpd.h"
#include "../lib/test.h"

#include <stdlib.h>
#include <string.h>

extern const dims_test dims_tests_unit_resize[];
extern const dims_test dims_tests_unit_crop[];
extern const dims_test dims_tests_unit_thumbnail[];
extern const dims_test dims_tests_unit_rotate[];
extern const dims_test dims_tests_unit_adjustments[];
extern const dims_test dims_tests_unit_output[];
extern const dims_test dims_tests_unit_watermark[];
extern const dims_test dims_tests_unit_encryption[];
extern const dims_test dims_tests_unit_netguard[];
extern const dims_test dims_tests_unit_overlay_cache[];
extern const dims_test dims_tests_unit_param[];
extern const dims_test dims_tests_unit_url[];

static const dims_test_group groups[] = {
    { "unit/test_resize.c", dims_tests_unit_resize },
    { "unit/test_crop.c", dims_tests_unit_crop },
    { "unit/test_thumbnail.c", dims_tests_unit_thumbnail },
    { "unit/test_rotate.c", dims_tests_unit_rotate },
    { "unit/test_adjustments.c", dims_tests_unit_adjustments },
    { "unit/test_output.c", dims_tests_unit_output },
    { "unit/test_watermark.c", dims_tests_unit_watermark },
    { "unit/test_encryption.c", dims_tests_unit_encryption },
    { "unit/test_netguard.c", dims_tests_unit_netguard },
    { "unit/test_overlay_cache.c", dims_tests_unit_overlay_cache },
    { "unit/test_param.c", dims_tests_unit_param },
    { "unit/test_url.c", dims_tests_unit_url },
    { NULL, NULL }
};

int
main(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) {
            dims_stub_log_enable(1);
        }
    }

    dims_fixture_init();

    return dims_test_main(groups, argc, argv);
}
