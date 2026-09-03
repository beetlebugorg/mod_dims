/*
 * The metrics block, shared by every worker.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "metrics.h"
#include "module.h"

#include <ap_mpm.h>

#include <curl/curl.h>

#include <stdio.h>
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

/* 304 answers a conditional request, so a caching client sees it often. */
static const int code_value[DIMS_CODE_COUNT - 1] = {
    200, 304, 400, 403, 404, 429, 500, 502, 503, 504
};

static const char *const code_name[DIMS_CODE_COUNT] = {
    "200", "304", "400", "403", "404", "429", "500", "502", "503", "504",
    "other"
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


/*
 * The end of a request, reached through a pool cleanup so that every return
 * path in the handler records exactly once.
 */
static apr_status_t
record_request(void *baton)
{
    dims_request_rec *d = (dims_request_rec *) baton;
    dims_metrics_rec *m = dims_metrics;
    int endpoint = d->endpoint;
    apr_uint64_t micros;

    if (m == NULL || endpoint < 0 || endpoint >= DIMS_ENDPOINT_COUNT) {
        return APR_SUCCESS;
    }

    apr_atomic_dec64(&m->in_flight[endpoint]);

    apr_atomic_inc64(&m->requests[endpoint]
            [dims_metrics_outcome_index(d->status)]);
    apr_atomic_inc64(&m->responses[endpoint]
            [dims_metrics_code_index(d->r->status)]);

    micros = (apr_uint64_t) (apr_time_now() - d->start_time);
    dims_metrics_observe(&m->request_duration[endpoint], &dims_duration_buckets,
            micros);

    /*
     * The source, when the request reached one. fetch_http_status names a
     * source fetch, and download_time alone names an error image fetch.
     * download_time counts milliseconds, so a fetch inside one millisecond
     * reports zero and belongs in the first bucket.
     */
    if (d->fetch_http_status != 0 || d->download_time > 0) {
        dims_metrics_observe(&m->download_duration, &dims_duration_buckets,
                (apr_uint64_t) d->download_time * 1000);
    }

    if (d->original_image_size > 0) {
        apr_atomic_add64(&m->source_bytes_total,
                (apr_uint64_t) d->original_image_size);
        dims_metrics_observe(&m->source_bytes, &dims_byte_buckets,
                (apr_uint64_t) d->original_image_size);
    }

    if (d->fetch_http_status != 0) {
        apr_atomic_inc64(&m->origin_responses[
                dims_metrics_origin_code_index(d->fetch_http_status)]);
    }

    if (d->source_format_index >= 0) {
        apr_atomic_inc64(&m->source_format[d->source_format_index]);
    }

    if (d->source_frames > 0) {
        dims_metrics_observe(&m->source_frames, &dims_frame_buckets,
                d->source_frames);
    }

    /* ImageMagick ran when it timed the work, whatever the outcome. */
    if (d->imagemagick_time > 0) {
        dims_metrics_observe(&m->imagemagick_duration, &dims_duration_buckets,
                (apr_uint64_t) d->imagemagick_time * 1000);
    }

    dims_metrics_sample_process();

    /* The response, when one was written. */
    if (d->output_format_index >= 0) {
        apr_atomic_inc64(&m->output_format[d->output_format_index]);
        apr_atomic_add64(&m->output_bytes_total, d->output_bytes);
        dims_metrics_observe(&m->output_bytes, &dims_byte_buckets,
                d->output_bytes);
    }

    return APR_SUCCESS;
}

void
dims_metrics_request_begin(dims_request_rec *d)
{
    if (dims_metrics == NULL || d->endpoint < 0 ||
            d->endpoint >= DIMS_ENDPOINT_COUNT) {
        return;
    }

    apr_atomic_inc64(&dims_metrics->in_flight[d->endpoint]);

    apr_pool_cleanup_register(d->r->pool, d, record_request,
            apr_pool_cleanup_null);
}

/*
 * The four ImageMagick resources the module limits, in the order the exposition
 * writer prints them.
 */
static const ResourceType resource_type[4] = {
    AreaResource, MemoryResource, MapResource, DiskResource
};

void
dims_metrics_sample_process(void)
{
    dims_process_rec *slot = my_process;
    FILE *statm;
    unsigned long resident = 0;
    unsigned long virtual = 0;
    int i;

    if (slot == NULL) {
        return;
    }

    for (i = 0; i < 4; i++) {
        slot->imagemagick_resource[i] =
                (apr_uint64_t) MagickGetResource(resource_type[i]);
    }

    /*
     * The first two fields of statm are the virtual size and the resident set,
     * both in pages. The file is Linux only, so a platform without it reports
     * zero and the writer omits the two gauges.
     */
    statm = fopen("/proc/self/statm", "r");
    if (statm == NULL) {
        return;
    }

    if (fscanf(statm, "%lu %lu", &virtual, &resident) == 2) {
        long page = sysconf(_SC_PAGESIZE);

        slot->virtual_bytes = (apr_uint64_t) virtual * (apr_uint64_t) page;
        slot->resident_bytes = (apr_uint64_t) resident * (apr_uint64_t) page;
    }

    fclose(statm);
}

/* libcurl codes reported by name. The rest count under "other". */
static const int curl_code_value[DIMS_CURL_CODE_COUNT - 1] = {
    CURLE_OPERATION_TIMEDOUT,
    CURLE_COULDNT_RESOLVE_HOST,
    CURLE_COULDNT_CONNECT,
    CURLE_SSL_CONNECT_ERROR,
    CURLE_TOO_MANY_REDIRECTS,
    CURLE_RECV_ERROR,
    CURLE_SEND_ERROR,
    CURLE_PARTIAL_FILE
};

static const char *const curl_code_name[DIMS_CURL_CODE_COUNT] = {
    "operation_timedout", "couldnt_resolve_host", "couldnt_connect",
    "ssl_connect_error", "too_many_redirects", "recv_error", "send_error",
    "partial_file", "other"
};

static const char *const fetch_result_name[DIMS_FETCH_RESULT_COUNT] = {
    "ok", "timeout", "transport_error", "refused", "http_error"
};

/* Indexed by dims_net_result, which starts at DIMS_NET_BAD_SCHEME. */
static const char *const net_reason_name[DIMS_NET_REASON_COUNT] = {
    "bad_scheme", "bad_url", "reserved_address", "private_address",
    "host_not_allowed", "too_many_redirects"
};

static const char *const sig_result_name[DIMS_SIG_RESULT_COUNT] = {
    "ok", "mismatch", "expired", "too_far_future", "missing_key", "bad_client"
};

/* The order dims_module.c registers them in the ops hash. */
static const char *const operation_name[DIMS_OP_COUNT] = {
    "strip", "resize", "crop", "thumbnail", "legacy_thumbnail", "legacy_crop",
    "quality", "sharpen", "format", "brightness", "flipflop", "sepia",
    "grayscale", "autolevel", "rotate", "invert", "watermark"
};

static const char *const exception_kind_name[DIMS_EXC_KIND_COUNT] = {
    "blob", "cache", "coder", "configure", "corrupt_image", "delegate",
    "draw", "file_open", "filter", "image", "missing_delegate", "module",
    "monitor", "option", "policy", "random", "registry", "resource_limit",
    "stream", "type", "wand", "other"
};

static const char *const exception_severity_name[DIMS_EXC_SEVERITY_COUNT] = {
    "warning", "error", "fatal"
};

int
dims_metrics_curl_code_index(int code)
{
    int i;

    for (i = 0; i < DIMS_CURL_CODE_COUNT - 1; i++) {
        if (curl_code_value[i] == code) {
            return i;
        }
    }

    return DIMS_CURL_CODE_COUNT - 1;
}

int
dims_metrics_operation_index(const char *operation)
{
    int i;

    if (operation == NULL) {
        return -1;
    }

    for (i = 0; i < DIMS_OP_COUNT; i++) {
        if (strcmp(operation_name[i], operation) == 0) {
            return i;
        }
    }

    return -1;
}

/*
 * ImageMagick names an exception by a kind and a severity in one enum, such as
 * ResourceLimitError. The two are separate signals: a warning about a coder
 * and a fatal cache failure read differently.
 */
void
dims_metrics_exception_slot(int exception_type, int *kind, int *severity)
{
    struct { int warning; int kind; } table[] = {
        { BlobWarning,            0  },
        { CacheWarning,           1  },
        { CoderWarning,           2  },
        { ConfigureWarning,       3  },
        { CorruptImageWarning,    4  },
        { DelegateWarning,        5  },
        { DrawWarning,            6  },
        { FileOpenWarning,        7  },
        { FilterWarning,          8  },
        { ImageWarning,           9  },
        { MissingDelegateWarning, 10 },
        { ModuleWarning,          11 },
        { MonitorWarning,         12 },
        { OptionWarning,          13 },
        { PolicyWarning,          14 },
        { RandomWarning,          15 },
        { RegistryWarning,        16 },
        { ResourceLimitWarning,   17 },
        { StreamWarning,          18 },
        { TypeWarning,            19 },
        { WandWarning,            20 }
    };
    size_t i;

    *kind = DIMS_EXC_KIND_COUNT - 1;
    *severity = 1;

    /* Each kind occupies three consecutive values: warning, error, and fatal
     * error. WandWarning has no fatal member, so it holds two. */
    for (i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        int offset = exception_type - table[i].warning;

        if (offset >= 0 && offset <= 2) {
            *kind = table[i].kind;
            *severity = offset;
            return;
        }
    }
}

const char *
dims_metrics_curl_code_name(int index)
{
    return (index < 0 || index >= DIMS_CURL_CODE_COUNT) ? ""
            : curl_code_name[index];
}

const char *
dims_metrics_operation_name(int index)
{
    return (index < 0 || index >= DIMS_OP_COUNT) ? "" : operation_name[index];
}

const char *
dims_metrics_exception_kind_name(int index)
{
    return (index < 0 || index >= DIMS_EXC_KIND_COUNT) ? ""
            : exception_kind_name[index];
}

const char *
dims_metrics_exception_severity_name(int index)
{
    return (index < 0 || index >= DIMS_EXC_SEVERITY_COUNT) ? ""
            : exception_severity_name[index];
}

const char *
dims_metrics_fetch_result_name(int index)
{
    return (index < 0 || index >= DIMS_FETCH_RESULT_COUNT) ? ""
            : fetch_result_name[index];
}

const char *
dims_metrics_net_reason_name(int index)
{
    return (index < 0 || index >= DIMS_NET_REASON_COUNT) ? ""
            : net_reason_name[index];
}

const char *
dims_metrics_sig_result_name(int index)
{
    return (index < 0 || index >= DIMS_SIG_RESULT_COUNT) ? ""
            : sig_result_name[index];
}

void
dims_metrics_signature(int endpoint, dims_sig_result result)
{
    if (dims_metrics == NULL || endpoint < 0 ||
            endpoint >= DIMS_ENDPOINT_COUNT) {
        return;
    }

    apr_atomic_inc64(&dims_metrics->signature[endpoint][result]);
}

void
dims_metrics_eurl(int ok)
{
    if (dims_metrics != NULL) {
        apr_atomic_inc64(&dims_metrics->eurl[ok ? 0 : 1]);
    }
}

void
dims_metrics_netguard(int reason)
{
    /* DIMS_NET_OK is zero and names no refusal. */
    if (dims_metrics == NULL || reason < 1 ||
            reason > DIMS_NET_REASON_COUNT) {
        return;
    }

    apr_atomic_inc64(&dims_metrics->netguard[reason - 1]);
}

void
dims_metrics_allowlist(int mode, int allowed)
{
    if (dims_metrics == NULL || mode < 0 || mode > 2) {
        return;
    }

    apr_atomic_inc64(&dims_metrics->allowlist[mode][allowed ? 0 : 1]);
}

void
dims_metrics_operation(int op_index, int from_default, apr_time_t began,
                       int failed)
{
    dims_metrics_rec *m = dims_metrics;

    if (m == NULL || op_index < 0 || op_index >= DIMS_OP_COUNT) {
        return;
    }

    apr_atomic_inc64(&m->operations[op_index][from_default ? 1 : 0]);

    if (failed) {
        apr_atomic_inc64(&m->operation_failures[op_index]);
    }

    dims_metrics_observe(&m->operation_duration[op_index],
            &dims_duration_buckets, (apr_uint64_t) (apr_time_now() - began));
}

void
dims_metrics_exception(int exception_type)
{
    int kind;
    int severity;

    if (dims_metrics == NULL || exception_type == UndefinedException) {
        return;
    }

    dims_metrics_exception_slot(exception_type, &kind, &severity);
    apr_atomic_inc64(&dims_metrics->exceptions[kind][severity]);
}

void
dims_metrics_overlay_lookup(int result)
{
    if (dims_metrics != NULL && result >= 0 && result < 3) {
        apr_atomic_inc64(&dims_metrics->overlay_lookups[result]);
    }
}

void
dims_metrics_overlay_eviction(void)
{
    if (dims_metrics != NULL) {
        apr_atomic_inc64(&dims_metrics->overlay_evictions);
    }
}

void
dims_metrics_fetch(dims_fetch_result result, int curl_code)
{
    if (dims_metrics == NULL) {
        return;
    }

    apr_atomic_inc64(&dims_metrics->fetch_results[result]);

    if (result == DIMS_FETCH_TIMEOUT || result == DIMS_FETCH_TRANSPORT_ERROR ||
            result == DIMS_FETCH_REFUSED) {
        apr_atomic_inc64(&dims_metrics->fetch_errors[
                dims_metrics_curl_code_index(curl_code)]);
    }
}

void
dims_metrics_error_image(int source, int failed)
{
    if (dims_metrics == NULL || source < 0 || source > 2) {
        return;
    }

    apr_atomic_inc64(&dims_metrics->error_images[source]);

    if (failed) {
        apr_atomic_inc64(&dims_metrics->error_image_failures);
    }
}
