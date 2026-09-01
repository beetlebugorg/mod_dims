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

/*
 * A request moves its counter. The value is read before and after, because
 * other cases in the run share the server and its counters.
 */
static void
test_metrics_counts_a_success(void)
{
    dims_response *before = scrape();
    double was = dims_prom_value(before,
            "dims_requests_total{endpoint=\"dims4\",outcome=\"success\"}");
    dims_response *image;
    dims_response *after;

    image = dims_request_ops("resize/40x40", "grid.png");
    CHECK_INT(image->status, 200, "the image request");
    dims_response_free(image);

    after = scrape();
    CHECK(dims_prom_value(after,
                  "dims_requests_total{endpoint=\"dims4\",outcome=\"success\"}")
              >= was + 1,
          "the success counter moved from %g", was);
    CHECK(dims_prom_value(after,
                  "dims_responses_total{endpoint=\"dims4\",code=\"200\"}")
              >= 1,
          "the 200 counter");

    dims_response_free(before);
    dims_response_free(after);
}

/*
 * A host outside the allowlist reports its own outcome on /dims3/, which is
 * the endpoint that enforces the list.
 */
static void
test_metrics_counts_a_refusal(void)
{
    dims_response *before = scrape();
    double was = dims_prom_value(before, "dims_requests_total{endpoint=\"dims3\","
            "outcome=\"hostname_not_in_whitelist\"}");
    dims_response *refused;
    dims_response *after;

    refused = dims_get("/dims3/TEST/resize/40x40/"
            "?url=http://notallowed:8080/grid.png");
    dims_response_free(refused);

    after = scrape();
    CHECK(dims_prom_value(after, "dims_requests_total{endpoint=\"dims3\","
                  "outcome=\"hostname_not_in_whitelist\"}") >= was + 1,
          "the refusal counter moved from %g", was);
    CHECK(dims_prom_value(after,
                  "dims_request_duration_seconds_count{endpoint=\"dims3\"}")
              >= 1,
          "the duration histogram counted it");

    dims_response_free(before);
    dims_response_free(after);
}

/* Nothing is in flight while the scrape runs, because the scrape is not. */
static void
test_metrics_in_flight_settles(void)
{
    dims_response *response = scrape();

    CHECK_INT((long) dims_prom_value(response,
                      "dims_requests_in_flight{endpoint=\"dims4\"}"),
              0, "in flight after the request ended");

    dims_response_free(response);
}

/* A fetch records its origin status, its size, and the format it read. */
static void
test_metrics_counts_the_source(void)
{
    dims_response *image = dims_request_ops("resize/40x40", "grid.png");
    dims_response *after;

    CHECK_INT(image->status, 200, "the image request");
    dims_response_free(image);

    after = scrape();

    CHECK(dims_prom_value(after, "dims_origin_responses_total{code=\"200\"}")
              >= 1,
          "the origin 200 counter");
    CHECK(dims_prom_value(after, "dims_source_format_total{format=\"png\"}")
              >= 1,
          "the PNG source counter");
    CHECK(dims_prom_value(after, "dims_source_bytes_total") > 0,
          "the source byte total");
    CHECK(dims_prom_value(after, "dims_source_bytes_count") >= 1,
          "the source size histogram");
    CHECK(dims_prom_value(after, "dims_source_fetch_duration_seconds_count")
              >= 1,
          "the fetch duration histogram");

    dims_response_free(after);
}

const dims_test dims_tests_metrics[] = {
    { "TestMetricsContentType", test_metrics_content_type, NULL },
    { "TestMetricsFormat", test_metrics_format, NULL },
    { "TestMetricsHistograms", test_metrics_histograms, NULL },
    { "TestMetricsFamilies", test_metrics_families, NULL },
    { "TestMetricsCountsASuccess", test_metrics_counts_a_success, NULL },
    { "TestMetricsCountsARefusal", test_metrics_counts_a_refusal, NULL },
    { "TestMetricsInFlightSettles", test_metrics_in_flight_settles, NULL },
    { "TestMetricsCountsTheSource", test_metrics_counts_the_source, NULL },
    { "TestMetricsDisabled", test_metrics_disabled, NULL },
    DIMS_TEST_END
};
