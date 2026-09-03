/*
 * The status handler.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"
#include "../lib/prometheus.h"

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
 * The handler returns the mod_dims, ImageMagick, and libcurl
 * versions to any caller.
 */
static void
test_status_hides_versions(void)
{
    dims_response *response = dims_get("/dims-status/");

    CHECK(strstr((const char *) response->body, "ImageMagick version") == NULL,
          "the status handler discloses the ImageMagick version");

    dims_response_free(response);
}

/*
 * The two endpoints read the same counters, so the success line matches the
 * sum of dims_requests_total across the endpoints.
 */
static void
test_status_agrees_with_the_metrics(void)
{
    dims_response *status;
    dims_response *metrics;
    const char *line;
    char scraped[64];
    double total = 0;
    static const char *const endpoints[] = {
        "dims3", "dims4", "dims5", "local", NULL
    };
    int i;

    dims_response_free(dims_request_ops("resize/40x40", "grid.png"));

    metrics = dims_get("/metrics");
    for (i = 0; endpoints[i] != NULL; i++) {
        char name[128];

        snprintf(name, sizeof(name),
                "dims_requests_total{endpoint=\"%s\",outcome=\"success\"}",
                endpoints[i]);
        total += dims_prom_value(metrics, name);
    }

    status = dims_get("/dims-status/");
    line = strstr((const char *) status->body, "Successful requests: ");

    if (line == NULL) {
        FAIL("the status page reports no success count");
    } else {
        snprintf(scraped, sizeof(scraped), "%s",
                line + strlen("Successful requests: "));
        CHECK_INT(atol(scraped), (long) total,
                  "the status count matches the metrics");
    }

    dims_response_free(status);
    dims_response_free(metrics);
}

const dims_test dims_tests_status[] = {
    { "TestStatusIsAlive", test_status_is_alive, NULL },
    { "TestStatusAgreesWithTheMetrics", test_status_agrees_with_the_metrics,
      NULL },
    { "TestStatusHidesVersions", test_status_hides_versions,
      "the versions print unless the directive is set" },
    DIMS_TEST_END
};
