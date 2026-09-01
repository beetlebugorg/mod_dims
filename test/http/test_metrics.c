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
 * A host outside the allowlist reports its own outcome on /dims3/. That is
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

/* A response reports its format, its size, and the ImageMagick time. */
static void
test_metrics_counts_the_output(void)
{
    dims_response *before = scrape();
    double was = dims_prom_value(before,
            "dims_output_format_total{format=\"webp\"}");
    dims_response *image;
    dims_response *after;

    image = dims_request_ops("resize/40x40/format/webp", "grid.png");
    CHECK_INT(image->status, 200, "the image request");
    dims_response_free(image);

    after = scrape();

    CHECK(dims_prom_value(after, "dims_output_format_total{format=\"webp\"}")
              >= was + 1,
          "the webp output counter moved from %g", was);
    CHECK(dims_prom_value(after, "dims_output_bytes_total") > 0,
          "the output byte total");
    CHECK(dims_prom_value(after, "dims_output_bytes_count") >= 1,
          "the output size histogram");
    CHECK(dims_prom_value(after, "dims_imagemagick_duration_seconds_count")
              >= 1,
          "the ImageMagick duration histogram");

    dims_response_free(before);
    dims_response_free(after);
}

/* A single frame source counts in the first bucket. */
static void
test_metrics_counts_frames(void)
{
    dims_response *image = dims_request_ops("resize/40x40", "grid.png");
    dims_response *after;

    dims_response_free(image);
    after = scrape();

    CHECK(dims_prom_value(after, "dims_source_frames_count") >= 1,
          "the frame histogram counted a source");
    CHECK(dims_prom_value(after, "dims_source_frames_bucket{le=\"1\"}") >= 1,
          "a single frame source is the first bucket");

    dims_response_free(after);
}

/*
 * The limits come from the configuration, so the reported ceiling matches what
 * dims-test.conf sets. The use is per worker and the endpoint sums the slots.
 */
static void
test_metrics_reports_resources(void)
{
    dims_response *response;

    /* A request first, so a worker has sampled itself. */
    dims_response_free(dims_request_ops("resize/40x40", "grid.png"));

    response = scrape();

    CHECK_INT((long) dims_prom_value(response,
                      "dims_imagemagick_resource_limit_bytes{resource=\"memory\"}"),
              536870912, "the memory limit");
    CHECK_INT((long) dims_prom_value(response,
                      "dims_imagemagick_resource_limit_bytes{resource=\"disk\"}"),
              2147483648L, "the disk limit");
    CHECK(dims_prom_value(response, "dims_workers") >= 1,
          "a worker holds a slot");
    CHECK(dims_prom_value(response, "dims_process_resident_bytes") > 0,
          "resident memory");
    CHECK(dims_prom_value(response, "dims_process_resident_max_bytes") > 0,
          "the widest worker");

    dims_response_free(response);
}

/*
 * The scoreboard holds a slot per thread across the daemon ceiling, so the
 * states add up to the ceiling times the thread count. The scrape itself is a
 * busy worker, so at least one is not ready.
 */
static void
test_metrics_reports_the_worker_pool(void)
{
    dims_response *response = scrape();
    static const char *const states[] = {
        "dead", "starting", "ready", "busy_read", "busy_write",
        "busy_keepalive", "busy_log", "busy_dns", "closing", "graceful",
        "idle_kill", NULL
    };
    char name[128];
    double total = 0;
    double limit;
    double threads;
    int i;

    for (i = 0; states[i] != NULL; i++) {
        snprintf(name, sizeof(name), "dims_httpd_workers{state=\"%s\"}",
                states[i]);
        total += dims_prom_value(response, name);
    }

    limit = dims_prom_value(response, "dims_httpd_processes_limit");
    threads = dims_prom_value(response, "dims_httpd_threads_per_process");

    CHECK(limit >= 1, "a daemon ceiling");
    CHECK(threads >= 1, "a thread count");
    CHECK_INT((long) total, (long) (limit * threads),
              "the worker states add up to the scoreboard");

    CHECK(dims_prom_value(response, "dims_httpd_processes") >= 1,
          "a live process");
    CHECK(dims_prom_value(response, "dims_httpd_workers{state=\"busy_write\"}")
              >= 1,
          "the scrape is a busy worker");

    dims_response_free(response);
}

/* The build gauge names the versions, and the start time is a real clock. */
static void
test_metrics_reports_the_build(void)
{
    dims_response *response = scrape();

    CHECK(dims_prom_contains(response, "dims_build_info{version=\""),
          "the build gauge");
    CHECK(dims_prom_contains(response, "imagemagick=\"ImageMagick"),
          "the ImageMagick version");

    /* Later than 2020, so the value is a clock rather than an uptime. */
    CHECK(dims_prom_value(response, "dims_start_time_seconds") > 1577836800.0,
          "the start time is an epoch second");

    dims_response_free(response);
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
    { "TestMetricsCountsTheOutput", test_metrics_counts_the_output, NULL },
    { "TestMetricsCountsFrames", test_metrics_counts_frames, NULL },
    { "TestMetricsReportsResources", test_metrics_reports_resources, NULL },
    { "TestMetricsReportsTheWorkerPool", test_metrics_reports_the_worker_pool,
      NULL },
    { "TestMetricsReportsTheBuild", test_metrics_reports_the_build, NULL },
    { "TestMetricsDisabled", test_metrics_disabled, NULL },
    DIMS_TEST_END
};
