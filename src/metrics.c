/*
 * The metrics block, shared by every worker.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "metrics.h"
#include "module.h"

#include <ap_mpm.h>

#include <unistd.h>
#include <strings.h>

dims_metrics_rec *dims_metrics;

static apr_shm_t *metrics_shm;

/* The slot this child claimed in dims_metrics_child_init. */
static dims_process_rec *my_process;

static const double duration_bound[] = {
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
};

static const double byte_bound[] = {
    16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864
};

static const double frame_bound[] = {
    1, 2, 4, 8, 16, 32, 64, 128
};

const dims_bucket_spec dims_duration_buckets = {
    duration_bound, (int) (sizeof(duration_bound) / sizeof(duration_bound[0]))
};

const dims_bucket_spec dims_byte_buckets = {
    byte_bound, (int) (sizeof(byte_bound) / sizeof(byte_bound[0]))
};

const dims_bucket_spec dims_frame_buckets = {
    frame_bound, (int) (sizeof(frame_bound) / sizeof(frame_bound[0]))
};

/* Indexed by dims_endpoint_t. */
static const char *const endpoint_name[] = {
    "dims3", "dims4", "dims5", "local"
};

/* Indexed by dims_status_t, which starts at DIMS_SUCCESS. */
static const char *const outcome_name[DIMS_OUTCOME_COUNT] = {
    "success",
    "failure",
    "download_timeout",
    "imagemagick_timeout",
    "bad_client",
    "bad_url",
    "bad_arguments",
    "hostname_not_in_whitelist",
    "file_not_found",
    "network_refused"
};

static const int code_value[DIMS_CODE_COUNT - 1] = {
    200, 400, 403, 404, 429, 500, 502, 503, 504
};

static const char *const code_name[DIMS_CODE_COUNT] = {
    "200", "400", "403", "404", "429", "500", "502", "503", "504", "other"
};

static const int origin_code_value[DIMS_ORIGIN_CODE_COUNT - 1] = {
    200, 301, 302, 304, 400, 403, 404, 429, 500, 502, 503, 504
};

static const char *const origin_code_name[DIMS_ORIGIN_CODE_COUNT] = {
    "200", "301", "302", "304", "400", "403", "404", "429",
    "500", "502", "503", "504", "other"
};

static const char *const format_name[DIMS_FORMAT_COUNT] = {
    "jpeg", "png", "gif", "webp", "avif", "heic", "tiff", "svg", "other"
};

apr_status_t
dims_metrics_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t status;
    apr_size_t size;
    int daemons = 0;

    if (ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &daemons) != APR_SUCCESS ||
            daemons < 1) {
        daemons = 1;
    }

    size = sizeof(dims_metrics_rec) +
            ((apr_size_t) daemons * sizeof(dims_process_rec));

    status = apr_shm_create(&metrics_shm, size, NULL, p);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, status, s,
                "mod_dims: the metrics block was not created");
        return status;
    }

    dims_metrics = apr_shm_baseaddr_get(metrics_shm);
    if (dims_metrics == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                "mod_dims: the metrics block has no address");
        return APR_EGENERAL;
    }

    memset(dims_metrics, 0, size);
    dims_metrics->process_slots = (apr_uint32_t) daemons;

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
            "mod_dims: the metrics block is %" APR_SIZE_T_FMT " bytes, "
            "with %d process slots", size, daemons);

    return APR_SUCCESS;
}

void
dims_metrics_child_init(void)
{
    apr_uint32_t i;
    apr_uint64_t pid;

    if (dims_metrics == NULL) {
        return;
    }

    pid = (apr_uint64_t) getpid();

    /* The first slot holding zero, or a slot left by a child that died. A
     * losing compare and swap means another child took it, so try the next. */
    for (i = 0; i < dims_metrics->process_slots; i++) {
        dims_process_rec *slot = &dims_metrics->process[i];

        if (apr_atomic_cas32((apr_uint32_t *) &slot->pid, (apr_uint32_t) pid,
                    0) == 0) {
            slot->resident_bytes = 0;
            slot->virtual_bytes = 0;
            memset(slot->imagemagick_resource, 0,
                    sizeof(slot->imagemagick_resource));
            my_process = slot;
            return;
        }
    }
}

dims_process_rec *
dims_metrics_process(void)
{
    return my_process;
}

int
dims_metrics_outcome_index(int status)
{
    if (status < DIMS_SUCCESS || status >= DIMS_OUTCOME_COUNT) {
        return DIMS_OUTCOME_COUNT - 1;
    }

    return status;
}

int
dims_metrics_code_index(int code)
{
    int i;

    for (i = 0; i < DIMS_CODE_COUNT - 1; i++) {
        if (code_value[i] == code) {
            return i;
        }
    }

    return DIMS_CODE_COUNT - 1;
}

int
dims_metrics_origin_code_index(int code)
{
    int i;

    for (i = 0; i < DIMS_ORIGIN_CODE_COUNT - 1; i++) {
        if (origin_code_value[i] == code) {
            return i;
        }
    }

    return DIMS_ORIGIN_CODE_COUNT - 1;
}

int
dims_metrics_format_index(const char *format)
{
    int i;

    if (format == NULL) {
        return DIMS_FORMAT_COUNT - 1;
    }

    /* ImageMagick reports JPG for a JPEG, and the two name one format. */
    if (strcasecmp(format, "jpg") == 0) {
        return 0;
    }

    for (i = 0; i < DIMS_FORMAT_COUNT - 1; i++) {
        if (strcasecmp(format_name[i], format) == 0) {
            return i;
        }
    }

    return DIMS_FORMAT_COUNT - 1;
}

const char *
dims_metrics_endpoint_name(int index)
{
    if (index < 0 || index >= DIMS_ENDPOINT_COUNT) {
        return "";
    }

    return endpoint_name[index];
}

const char *
dims_metrics_outcome_name(int index)
{
    if (index < 0 || index >= DIMS_OUTCOME_COUNT) {
        return "";
    }

    return outcome_name[index];
}

const char *
dims_metrics_code_name(int index)
{
    if (index < 0 || index >= DIMS_CODE_COUNT) {
        return "";
    }

    return code_name[index];
}

const char *
dims_metrics_origin_code_name(int index)
{
    if (index < 0 || index >= DIMS_ORIGIN_CODE_COUNT) {
        return "";
    }

    return origin_code_name[index];
}

const char *
dims_metrics_format_name(int index)
{
    if (index < 0 || index >= DIMS_FORMAT_COUNT) {
        return "";
    }

    return format_name[index];
}

int
dims_metrics_bucket_index(const dims_bucket_spec *spec, double value)
{
    int i;

    for (i = 0; i < spec->bounds; i++) {
        if (value <= spec->bound[i]) {
            return i;
        }
    }

    return spec->bounds;
}

void
dims_metrics_observe(dims_histogram_rec *h, const dims_bucket_spec *spec,
                     apr_uint64_t value)
{
    double scaled = (spec == &dims_duration_buckets)
            ? (double) value / 1000000.0
            : (double) value;

    apr_atomic_inc64(&h->bucket[dims_metrics_bucket_index(spec, scaled)]);
    apr_atomic_add64(&h->sum, value);
    apr_atomic_inc64(&h->count);
}

