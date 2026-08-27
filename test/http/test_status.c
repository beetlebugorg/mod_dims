/*
 * The status handler.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

static void
test_status_is_alive(void)
{
    dims_response *response = dims_get("/dims-status/");

    CHECK_INT(response->status, 200, "the status handler");
    CHECK(response->body != NULL && strncmp((const char *) response->body, "ALIVE", 5) == 0,
          "the status body must start with ALIVE");

    dims_response_free(response);
}

/*
 * Finding M17. The handler returns the mod_dims, ImageMagick, and libcurl
 * versions to any caller. PR 17 puts them behind DimsStatusVerbose.
 */
static void
test_status_hides_versions(void)
{
    dims_response *response = dims_get("/dims-status/");

    CHECK(strstr((const char *) response->body, "ImageMagick version") == NULL,
          "the status handler discloses the ImageMagick version");

    dims_response_free(response);
}

const dims_test dims_tests_status[] = {
    { "TestStatusIsAlive", test_status_is_alive, NULL },
    { "TestStatusHidesVersions", test_status_hides_versions, "M17" },
    DIMS_TEST_END
};
