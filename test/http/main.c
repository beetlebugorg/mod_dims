/*
 * The entry point. The group table is explicit so a case cannot be added to a
 * file and silently never run.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/test.h"

#include "../lib/request.h"

#include <curl/curl.h>
#include <stdio.h>

extern const dims_test dims_tests_resize[];
extern const dims_test dims_tests_crop[];
extern const dims_test dims_tests_thumbnail[];
extern const dims_test dims_tests_rotate[];
extern const dims_test dims_tests_adjustments[];
extern const dims_test dims_tests_output[];
extern const dims_test dims_tests_watermark[];
extern const dims_test dims_tests_sources[];
extern const dims_test dims_tests_signing[];
extern const dims_test dims_tests_allowlist[];
extern const dims_test dims_tests_cache_headers[];
extern const dims_test dims_tests_errors[];
extern const dims_test dims_tests_status[];
extern const dims_test dims_tests_no_error_image[];
extern const dims_test dims_tests_source_limit[];

static const dims_test_group groups[] = {
    { "test_resize.c", dims_tests_resize },
    { "test_crop.c", dims_tests_crop },
    { "test_thumbnail.c", dims_tests_thumbnail },
    { "test_rotate.c", dims_tests_rotate },
    { "test_adjustments.c", dims_tests_adjustments },
    { "test_output.c", dims_tests_output },
    { "test_watermark.c", dims_tests_watermark },
    { "test_sources.c", dims_tests_sources },
    { "test_signing.c", dims_tests_signing },
    { "test_allowlist.c", dims_tests_allowlist },
    { "test_cache_headers.c", dims_tests_cache_headers },
    { "test_errors.c", dims_tests_errors },
    { "test_status.c", dims_tests_status },
    { "test_no_error_image.c", dims_tests_no_error_image },
    { "test_source_limit.c", dims_tests_source_limit },
    { NULL, NULL }
};

int
main(int argc, char **argv)
{
    int status;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* compose starts the containers, it does not wait for httpd to bind. */
    if (dims_wait_for_service(dims_base_url(), 60) != 0) {
        fprintf(stderr, "the dims service did not answer at %s\n", dims_base_url());
        return 2;
    }
    if (dims_wait_for_service(dims_origin_url(), 60) != 0) {
        fprintf(stderr, "the origin service did not answer at %s\n", dims_origin_url());
        return 2;
    }
    status = dims_test_main(groups, argc, argv);
    curl_global_cleanup();

    return status;
}
