/*
 * The metrics endpoint.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "metrics.h"
#include "module.h"

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

static void
write_metrics(request_rec *r)
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
        write_metrics(r);
        ap_rflush(r);
    }

    return OK;
}
