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

    write_process(r, m);
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
