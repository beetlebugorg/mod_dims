/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"
#include "../lib/prometheus.h"

/* The server that sets the handler and turns DimsMetricsEnabled off. */
static const char *
metrics_off_url(void)
{
    const char *from_env = getenv("DIMS_TEST_METRICS_OFF_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8009";
}

static dims_response *
scrape(void)
{
    char url[512];

    snprintf(url, sizeof(url), "%s/metrics", dims_base_url());

    return dims_get_absolute(url);
}

static void
test_metrics_content_type(void)
{
    dims_response *response = scrape();
    const char *type;

    CHECK_INT(response->status, 200, "the metrics endpoint");

    type = dims_header_value(response, "Content-Type");
    CHECK(type != NULL && strstr(type, "text/plain") != NULL &&
              strstr(type, "version=0.0.4") != NULL,
          "the Prometheus content type, got %s", type ? type : "none");

    dims_response_free(response);
}

/*
 * Every line is a comment or a sample. A sample is a name, an optional label
 * set in braces, a space, and a value.
 */
static void
test_metrics_format(void)
{
    dims_response *response = scrape();
    char *body;
    char *line;
    char *state = NULL;
    int samples = 0;

    body = malloc(response->body_len + 1);
    if (body == NULL) {
        FAIL("out of memory");
        dims_response_free(response);
        return;
    }

    memcpy(body, response->body, response->body_len);
    body[response->body_len] = '\0';

    for (line = strtok_r(body, "\n", &state); line != NULL;
            line = strtok_r(NULL, "\n", &state)) {
        if (strncmp(line, "# HELP ", 7) == 0 ||
                strncmp(line, "# TYPE ", 7) == 0) {
            continue;
        }

        if (strchr(line, ' ') == NULL) {
            FAIL("a line with no value: %s", line);
            break;
        }

        samples++;
    }

    CHECK(samples > 50, "the page reports samples, got %d", samples);

    free(body);
    dims_response_free(response);
}

/* A histogram reports a bucket per bound, a +Inf bucket, a sum, and a count. */
static void
test_metrics_histograms(void)
{
    dims_response *response = scrape();

    CHECK(dims_prom_contains(response,
                  "dims_request_duration_seconds_bucket{endpoint=\"dims4\","
                  "le=\"+Inf\"}"),
          "the request duration +Inf bucket");
    CHECK(dims_prom_contains(response, "dims_request_duration_seconds_sum{"),
          "the request duration sum");
    CHECK(dims_prom_contains(response, "dims_request_duration_seconds_count{"),
          "the request duration count");
    CHECK(dims_prom_contains(response, "dims_source_bytes_bucket{le=\"16384\"}"),
          "a byte bucket");

    /* A bound prints exactly. Six significant digits round 1048576 to
     * 1048580, which names a bucket no dashboard expects. */
    CHECK(dims_prom_contains(response,
                  "dims_source_bytes_bucket{le=\"1048576\"}"),
          "the one megabyte bound");
    CHECK(dims_prom_contains(response,
                  "dims_source_bytes_bucket{le=\"67108864\"}"),
          "the sixty four megabyte bound");
    CHECK(dims_prom_contains(response, "dims_request_duration_seconds_bucket{"
                  "endpoint=\"dims5\",le=\"0.005\"}"),
          "the five millisecond bound");

    /* A family with no labels prints no braces. */
    CHECK(!dims_prom_contains(response, "_count{} "),
          "no empty label set");

    dims_response_free(response);
}

/* Every family the block holds appears, whatever its value. */
static void
test_metrics_families(void)
{
    dims_response *response = scrape();
    static const char *const names[] = {
        "# TYPE dims_requests_total counter",
        "# TYPE dims_responses_total counter",
        "# TYPE dims_requests_in_flight gauge",
        "# TYPE dims_origin_responses_total counter",
        "# TYPE dims_source_format_total counter",
        "# TYPE dims_output_format_total counter",
        "# TYPE dims_source_bytes_total counter",
        "# TYPE dims_output_bytes_total counter",
        "# TYPE dims_imagemagick_duration_seconds histogram",
        "# TYPE dims_source_frames histogram",
        NULL
    };
    int i;

    for (i = 0; names[i] != NULL; i++) {
        CHECK(dims_prom_contains(response, names[i]), "%s", names[i]);
    }

    dims_response_free(response);
}

/* The directive is the switch. Off, the handler reports no metrics. */
static void
test_metrics_disabled(void)
{
    char url[512];
    dims_response *response;

    snprintf(url, sizeof(url), "%s/metrics", metrics_off_url());
    response = dims_get_absolute(url);

    CHECK_INT(response->status, 404, "DimsMetricsEnabled off");

    dims_response_free(response);
}

const dims_test dims_tests_metrics[] = {
    { "TestMetricsContentType", test_metrics_content_type, NULL },
    { "TestMetricsFormat", test_metrics_format, NULL },
    { "TestMetricsHistograms", test_metrics_histograms, NULL },
    { "TestMetricsFamilies", test_metrics_families, NULL },
    { "TestMetricsDisabled", test_metrics_disabled, NULL },
    DIMS_TEST_END
};
