/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

/* The server that removes the handler from both legacy endpoints. */
static const char *
legacy_off_url(void)
{
    const char *from_env = getenv("DIMS_TEST_LEGACY_OFF_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8008";
}

static long
status_of(const char *base, const char *path)
{
    char url[2048];
    dims_response *response;
    long status;

    snprintf(url, sizeof(url), "%s%s", base, path);
    response = dims_get_absolute(url);

    CHECK(response->transport_error == NULL, "%s: %s", path,
          response->transport_error ? response->transport_error : "");

    status = response->status;
    dims_response_free(response);

    return status;
}

#define DIMS3_PATH "/dims3/TEST/resize/100x100/?url=http://origin:8080/grid.png"
#define DIMS4_PATH "/dims4/TEST/deadbeef/resize/100x100/?url=http://origin:8080/grid.png"

/*
 * SetHandler None removes the handler the main server set. The module
 * dispatches on the handler, so httpd returns 404.
 */
static void
test_dims3_handler_removed(void)
{
    CHECK_INT(status_of(legacy_off_url(), DIMS3_PATH), 404,
              "/dims3/ with SetHandler None");
}

/* The same for /dims4/. */
static void
test_dims4_handler_removed(void)
{
    CHECK_INT(status_of(legacy_off_url(), DIMS4_PATH), 404,
              "/dims4/ with SetHandler None");
}

/* The default server sets both handlers, so neither path returns 404. */
static void
test_both_served_where_configured(void)
{
    long dims3 = status_of(dims_base_url(), DIMS3_PATH);
    long dims4 = status_of(dims_base_url(), DIMS4_PATH);

    CHECK(dims3 != 404, "/dims3/ is served, got %ld", dims3);
    CHECK(dims4 != 404, "/dims4/ is served, got %ld", dims4);
}

const dims_test dims_tests_legacy_endpoints[] = {
    { "TestDims3HandlerRemoved", test_dims3_handler_removed, NULL },
    { "TestDims4HandlerRemoved", test_dims4_handler_removed, NULL },
    { "TestLegacyEndpointsServedWhereConfigured", test_both_served_where_configured, NULL },
    DIMS_TEST_END
};
