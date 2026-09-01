/*
 * The metrics endpoint.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "metrics.h"
#include "module.h"

#include <ap_mpm.h>
#include <scoreboard.h>

#include <curl/curl.h>

#include <string.h>

#include <stdio.h>

/*
 * The exposition writer.
 *
 * Prometheus text 0.0.4. A family prints a # HELP line, a # TYPE line, and one
 * line per series. A histogram prints a cumulative _bucket line per bound,
 * then _sum and _count.
 */

static apr_uint64_t
read64(const apr_uint64_t *value)
{
    return apr_atomic_read64((apr_uint64_t *) value);
}

/*
 * A label value with the three characters the format reserves escaped: a
 * backslash, a double quote, and a newline. Every label the module writes is
 * its own, apart from the library versions, which come from ImageMagick and
 * libcurl.
 */
static const char *
escape(apr_pool_t *pool, const char *value)
{
    apr_size_t len;
    char *out;
    apr_size_t w = 0;
    apr_size_t i;

    if (value == NULL) {
        return "";
    }

    len = strlen(value);
    out = apr_palloc(pool, len * 2 + 1);

    for (i = 0; i < len; i++) {
        switch (value[i]) {
            case '\\': out[w++] = '\\'; out[w++] = '\\'; break;
            case '"':  out[w++] = '\\'; out[w++] = '"';  break;
            case '\n': out[w++] = '\\'; out[w++] = 'n';  break;
            default:   out[w++] = value[i];              break;
        }
    }

    out[w] = '\0';

    return out;
}

static void
head(request_rec *r, const char *name, const char *help, const char *type)
{
    ap_rprintf(r, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, type);
}

/*
 * labels is the label set without braces, such as endpoint="dims3". Pass an
 * empty string for a family with no labels.
 */
static void
histogram(request_rec *r, const char *name, const dims_histogram_rec *h,
          const dims_bucket_spec *spec, int seconds, const char *labels)
{
    apr_uint64_t running = 0;
    char braced[96];
    char bound[32];
    int i;

    for (i = 0; i < spec->bounds; i++) {
        running += read64(&h->bucket[i]);
        /* snprintf, because the httpd formatter prints .005 for 0.005 and
         * rounds 1048576 to 1048580. A dashboard matches le as a string. */
        snprintf(bound, sizeof(bound), "%.15g", spec->bound[i]);
        ap_rprintf(r, "%s_bucket{%s%sle=\"%s\"} %" APR_UINT64_T_FMT "\n",
                name, labels, labels[0] ? "," : "", bound, running);
    }

    running += read64(&h->bucket[spec->bounds]);
    ap_rprintf(r, "%s_bucket{%s%sle=\"+Inf\"} %" APR_UINT64_T_FMT "\n",
            name, labels, labels[0] ? "," : "", running);

    /* A family with no labels prints no braces. */
    if (labels[0] != '\0') {
        apr_snprintf(braced, sizeof(braced), "{%s}", labels);
    } else {
        braced[0] = '\0';
    }

    if (seconds) {
        ap_rprintf(r, "%s_sum%s %.6f\n", name, braced,
                (double) read64(&h->sum) / 1000000.0);
    } else {
        ap_rprintf(r, "%s_sum%s %" APR_UINT64_T_FMT "\n", name, braced,
                read64(&h->sum));
    }

    ap_rprintf(r, "%s_count%s %" APR_UINT64_T_FMT "\n", name, braced,
            read64(&h->count));
}

/*
 * The per process gauges. Each child writes its own slot at the end of a
 * request, so the endpoint sums the live slots and reports the widest one.
 */
static void
write_process(request_rec *r, const dims_metrics_rec *m)
{
    static const char *const resource[4] = { "area", "memory", "map", "disk" };
    apr_uint64_t sum[4] = { 0, 0, 0, 0 };
    apr_uint64_t max[4] = { 0, 0, 0, 0 };
    apr_uint64_t resident_sum = 0, resident_max = 0;
    apr_uint64_t virtual_sum = 0, virtual_max = 0;
    apr_uint32_t live = 0;
    apr_uint32_t i;
    int k;

    for (i = 0; i < m->process_slots; i++) {
        const dims_process_rec *slot = &m->process[i];
        apr_uint64_t resident;
        apr_uint64_t virt;

        if (read64(&slot->pid) == 0) {
            continue;
        }

        live++;

        for (k = 0; k < 4; k++) {
            apr_uint64_t value = read64(&slot->imagemagick_resource[k]);

            sum[k] += value;
            if (value > max[k]) {
                max[k] = value;
            }
        }

        resident = read64(&slot->resident_bytes);
        resident_sum += resident;
        if (resident > resident_max) {
            resident_max = resident;
        }

        virt = read64(&slot->virtual_bytes);
        virtual_sum += virt;
        if (virt > virtual_max) {
            virtual_max = virt;
        }
    }

    head(r, "dims_imagemagick_resource_bytes",
            "ImageMagick resource use, summed across the workers.", "gauge");
    for (k = 0; k < 4; k++) {
        ap_rprintf(r, "dims_imagemagick_resource_bytes{resource=\"%s\"} "
                "%" APR_UINT64_T_FMT "\n", resource[k], sum[k]);
    }

    head(r, "dims_imagemagick_resource_max_bytes",
            "ImageMagick resource use by the widest worker.", "gauge");
    for (k = 0; k < 4; k++) {
        ap_rprintf(r, "dims_imagemagick_resource_max_bytes{resource=\"%s\"} "
                "%" APR_UINT64_T_FMT "\n", resource[k], max[k]);
    }

    /* The ceiling a worker runs under, from the same process the scrape
     * reached. dims_child_init sets the same value in every worker. */
    head(r, "dims_imagemagick_resource_limit_bytes",
            "The DimsImagemagick limit a worker runs under.", "gauge");
    ap_rprintf(r, "dims_imagemagick_resource_limit_bytes{resource=\"area\"} "
            "%" APR_UINT64_T_FMT "\n",
            (apr_uint64_t) MagickGetResourceLimit(AreaResource));
    ap_rprintf(r, "dims_imagemagick_resource_limit_bytes{resource=\"memory\"} "
            "%" APR_UINT64_T_FMT "\n",
            (apr_uint64_t) MagickGetResourceLimit(MemoryResource));
    ap_rprintf(r, "dims_imagemagick_resource_limit_bytes{resource=\"map\"} "
            "%" APR_UINT64_T_FMT "\n",
            (apr_uint64_t) MagickGetResourceLimit(MapResource));
    ap_rprintf(r, "dims_imagemagick_resource_limit_bytes{resource=\"disk\"} "
            "%" APR_UINT64_T_FMT "\n",
            (apr_uint64_t) MagickGetResourceLimit(DiskResource));

    head(r, "dims_workers", "Worker processes holding a metrics slot.",
            "gauge");
    ap_rprintf(r, "dims_workers %" APR_UINT64_T_FMT "\n", (apr_uint64_t) live);

    /* /proc/self/statm is Linux only, so a platform without it reports no
     * memory rather than zero. */
    if (resident_sum > 0 || virtual_sum > 0) {
        head(r, "dims_process_resident_bytes",
                "Resident memory, summed across the workers.", "gauge");
        ap_rprintf(r, "dims_process_resident_bytes %" APR_UINT64_T_FMT "\n",
                resident_sum);

        head(r, "dims_process_resident_max_bytes",
                "Resident memory of the widest worker.", "gauge");
        ap_rprintf(r, "dims_process_resident_max_bytes %" APR_UINT64_T_FMT "\n",
                resident_max);

        head(r, "dims_process_virtual_bytes",
                "Virtual memory, summed across the workers.", "gauge");
        ap_rprintf(r, "dims_process_virtual_bytes %" APR_UINT64_T_FMT "\n",
                virtual_sum);
    }
}

/*
 * The httpd worker pool, read from the scoreboard rather than the metrics
 * block. The scoreboard is the server's own record, so a scrape reports what
 * every worker is doing now.
 */
static void
write_httpd(request_rec *r)
{
    static const char *const state_name[SERVER_NUM_STATUS] = {
        "dead", "starting", "ready", "busy_read", "busy_write",
        "busy_keepalive", "busy_log", "busy_dns", "closing", "graceful",
        "idle_kill"
    };
    apr_uint64_t state[SERVER_NUM_STATUS];
    apr_uint64_t connections = 0, write_completion = 0, lingering = 0;
    apr_uint64_t keep_alive = 0, suspended = 0;
    int daemons = 0, threads = 0, generation = 0;
    int processes = 0;
    int i, j;

    memset(state, 0, sizeof(state));

    ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &daemons);
    ap_mpm_query(AP_MPMQ_MAX_THREADS, &threads);
    ap_mpm_query(AP_MPMQ_GENERATION, &generation);

    if (threads < 1) {
        threads = 1;
    }

    if (ap_exists_scoreboard_image()) {
        for (i = 0; i < daemons; i++) {
            process_score *ps = ap_get_scoreboard_process(i);

            if (ps->pid != 0 && !ps->quiescing) {
                processes++;
                connections += ps->connections;
                write_completion += ps->write_completion;
                lingering += ps->lingering_close;
                keep_alive += ps->keep_alive;
                suspended += ps->suspended;
            }

            for (j = 0; j < threads; j++) {
                worker_score *ws = ap_get_scoreboard_worker_from_indexes(i, j);

                if (ws != NULL && ws->status < SERVER_NUM_STATUS) {
                    state[ws->status]++;
                }
            }
        }
    }

    head(r, "dims_httpd_workers", "Worker threads by scoreboard state.",
            "gauge");
    for (i = 0; i < SERVER_NUM_STATUS; i++) {
        ap_rprintf(r, "dims_httpd_workers{state=\"%s\"} %" APR_UINT64_T_FMT "\n",
                state_name[i], state[i]);
    }

    head(r, "dims_httpd_processes", "Child processes serving requests.",
            "gauge");
    ap_rprintf(r, "dims_httpd_processes %d\n", processes);

    head(r, "dims_httpd_processes_limit", "The daemon ceiling the MPM runs under.",
            "gauge");
    ap_rprintf(r, "dims_httpd_processes_limit %d\n", daemons);

    head(r, "dims_httpd_threads_per_process", "Threads in one child.", "gauge");
    ap_rprintf(r, "dims_httpd_threads_per_process %d\n", threads);

    head(r, "dims_httpd_connections", "Connections by state.", "gauge");
    ap_rprintf(r, "dims_httpd_connections{state=\"total\"} "
            "%" APR_UINT64_T_FMT "\n", connections);
    ap_rprintf(r, "dims_httpd_connections{state=\"write_completion\"} "
            "%" APR_UINT64_T_FMT "\n", write_completion);
    ap_rprintf(r, "dims_httpd_connections{state=\"lingering_close\"} "
            "%" APR_UINT64_T_FMT "\n", lingering);
    ap_rprintf(r, "dims_httpd_connections{state=\"keep_alive\"} "
            "%" APR_UINT64_T_FMT "\n", keep_alive);
    ap_rprintf(r, "dims_httpd_connections{state=\"suspended\"} "
            "%" APR_UINT64_T_FMT "\n", suspended);

    /* A restart increments this, so a dashboard sees the reload. */
    head(r, "dims_httpd_generation", "The MPM generation.", "gauge");
    ap_rprintf(r, "dims_httpd_generation %d\n", generation);
}

/*
 * The build and the start time.
 *
 * dims_build_info names every library version, so DimsStatusVerbose off drops
 * it the same way it drops the version lines from /dims-status/.
 */
static void
write_build(request_rec *r, const dims_config_rec *config)
{
    head(r, "dims_start_time_seconds",
            "When the server last started, in seconds since the epoch.",
            "gauge");
    ap_rprintf(r, "dims_start_time_seconds %" APR_TIME_T_FMT "\n",
            apr_time_sec(ap_scoreboard_image->global->restart_time));

    if (config == NULL || !config->status_verbose) {
        return;
    }

    head(r, "dims_build_info", "The running build, always 1.", "gauge");
    ap_rprintf(r, "dims_build_info{version=\"%s\",commit=\"%s\","
            "imagemagick=\"%s\",libcurl=\"%s\"} 1\n",
            escape(r->pool, DIMS_VERSION), escape(r->pool, DIMS_COMMIT),
            escape(r->pool, GetMagickVersion(NULL)),
            escape(r->pool, curl_version()));
}

static void
write_metrics(request_rec *r, const dims_config_rec *config)
{
    dims_metrics_rec *m = dims_metrics;
    char labels[64];
    int e, i;

    head(r, "dims_requests_total", "Requests by endpoint and outcome.",
            "counter");
    for (e = 0; e < DIMS_ENDPOINT_COUNT; e++) {
        for (i = 0; i < DIMS_OUTCOME_COUNT; i++) {
            ap_rprintf(r, "dims_requests_total{endpoint=\"%s\",outcome=\"%s\"} "
                    "%" APR_UINT64_T_FMT "\n",
                    dims_metrics_endpoint_name(e), dims_metrics_outcome_name(i),
                    read64(&m->requests[e][i]));
        }
    }

    head(r, "dims_responses_total", "Responses by endpoint and status code.",
            "counter");
    for (e = 0; e < DIMS_ENDPOINT_COUNT; e++) {
        for (i = 0; i < DIMS_CODE_COUNT; i++) {
            ap_rprintf(r, "dims_responses_total{endpoint=\"%s\",code=\"%s\"} "
                    "%" APR_UINT64_T_FMT "\n",
                    dims_metrics_endpoint_name(e), dims_metrics_code_name(i),
                    read64(&m->responses[e][i]));
        }
    }

    head(r, "dims_requests_in_flight", "Requests being served.", "gauge");
    for (e = 0; e < DIMS_ENDPOINT_COUNT; e++) {
        ap_rprintf(r, "dims_requests_in_flight{endpoint=\"%s\"} "
                "%" APR_UINT64_T_FMT "\n",
                dims_metrics_endpoint_name(e), read64(&m->in_flight[e]));
    }

    head(r, "dims_origin_responses_total",
            "Source fetches by the status the origin returned.", "counter");
    for (i = 0; i < DIMS_ORIGIN_CODE_COUNT; i++) {
        ap_rprintf(r, "dims_origin_responses_total{code=\"%s\"} "
                "%" APR_UINT64_T_FMT "\n",
                dims_metrics_origin_code_name(i),
                read64(&m->origin_responses[i]));
    }

    head(r, "dims_source_format_total", "Source images by format.", "counter");
    for (i = 0; i < DIMS_FORMAT_COUNT; i++) {
        ap_rprintf(r, "dims_source_format_total{format=\"%s\"} "
                "%" APR_UINT64_T_FMT "\n",
                dims_metrics_format_name(i), read64(&m->source_format[i]));
    }

    head(r, "dims_output_format_total", "Responses by image format.", "counter");
    for (i = 0; i < DIMS_FORMAT_COUNT; i++) {
        ap_rprintf(r, "dims_output_format_total{format=\"%s\"} "
                "%" APR_UINT64_T_FMT "\n",
                dims_metrics_format_name(i), read64(&m->output_format[i]));
    }

    head(r, "dims_source_bytes_total", "Bytes fetched from an origin.",
            "counter");
    ap_rprintf(r, "dims_source_bytes_total %" APR_UINT64_T_FMT "\n",
            read64(&m->source_bytes_total));

    head(r, "dims_output_bytes_total", "Bytes written to callers.", "counter");
    ap_rprintf(r, "dims_output_bytes_total %" APR_UINT64_T_FMT "\n",
            read64(&m->output_bytes_total));

    head(r, "dims_request_duration_seconds", "Time to serve a request.",
            "histogram");
    for (e = 0; e < DIMS_ENDPOINT_COUNT; e++) {
        apr_snprintf(labels, sizeof(labels), "endpoint=\"%s\"",
                dims_metrics_endpoint_name(e));
        histogram(r, "dims_request_duration_seconds", &m->request_duration[e],
                &dims_duration_buckets, 1, labels);
    }

    head(r, "dims_source_fetch_duration_seconds",
            "Time to fetch a source image.", "histogram");
    histogram(r, "dims_source_fetch_duration_seconds", &m->download_duration,
            &dims_duration_buckets, 1, "");

    head(r, "dims_imagemagick_duration_seconds", "Time inside ImageMagick.",
            "histogram");
    histogram(r, "dims_imagemagick_duration_seconds", &m->imagemagick_duration,
            &dims_duration_buckets, 1, "");

    head(r, "dims_source_bytes", "Source image size.", "histogram");
    histogram(r, "dims_source_bytes", &m->source_bytes, &dims_byte_buckets, 0,
            "");

    head(r, "dims_output_bytes", "Response image size.", "histogram");
    histogram(r, "dims_output_bytes", &m->output_bytes, &dims_byte_buckets, 0,
            "");

    head(r, "dims_source_frames", "Frames in a source image.", "histogram");
    histogram(r, "dims_source_frames", &m->source_frames, &dims_frame_buckets,
            0, "");

    write_process(r, m);
    write_httpd(r);
    write_build(r, config);
}

apr_status_t
dims_metrics_handler(request_rec *r)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            r->server->module_config, &dims_module);

    if (config == NULL || !config->metrics_enabled || dims_metrics == NULL) {
        return DECLINED;
    }

    if (r->method_number != M_GET) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    ap_set_content_type(r, "text/plain; version=0.0.4; charset=utf-8");

    if (!r->header_only) {
        write_metrics(r, config);
        ap_rflush(r);
    }

    return OK;
}
