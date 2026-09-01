/*
 * The metrics block, shared by every worker.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_METRICS_H
#define _DIMS_METRICS_H

#include "mod_dims.h"

/* The endpoint a request arrived on. */
typedef enum {
    DIMS_ENDPOINT_DIMS3 = 0,
    DIMS_ENDPOINT_DIMS4,
    DIMS_ENDPOINT_DIMS5,
    DIMS_ENDPOINT_LOCAL,
    DIMS_ENDPOINT_COUNT
} dims_endpoint_t;

/* One slot per dims_status_t, without DIMS_IGNORE. */
#define DIMS_OUTCOME_COUNT 10

/*
 * Response and origin status codes are reported by name from a list, because
 * DimsOriginStatusMode forward copies whatever the origin returned. The last
 * slot of each holds every code outside its list.
 */
#define DIMS_CODE_COUNT 11
#define DIMS_ORIGIN_CODE_COUNT 13

/* Image formats reported by name. The last slot holds every other format. */
#define DIMS_FORMAT_COUNT 9

/* Why a source fetch ended. */
#define DIMS_FETCH_RESULT_COUNT 5

/* libcurl error codes reported by name. The last slot holds every other one. */
#define DIMS_CURL_CODE_COUNT 9

/* dims_net_result without DIMS_NET_OK. */
#define DIMS_NET_REASON_COUNT 6

/* How a signature check ended. */
#define DIMS_SIG_RESULT_COUNT 6

/* The seventeen operations in the ops hash. */
#define DIMS_OP_COUNT 17

/* ImageMagick exception kinds, and the three severities. */
#define DIMS_EXC_KIND_COUNT 22
#define DIMS_EXC_SEVERITY_COUNT 3

/* The widest bucket table below, plus the +Inf bucket. */
#define DIMS_BUCKET_MAX 13

typedef struct {
    apr_uint64_t bucket[DIMS_BUCKET_MAX];
    apr_uint64_t sum;
    apr_uint64_t count;
} dims_histogram_rec;

/*
 * A bucket table. bound holds the finite upper bounds in ascending order, and
 * the table has bounds + 1 buckets, because the last one is +Inf.
 */
typedef struct {
    const double *bound;
    int bounds;
} dims_bucket_spec;

extern const dims_bucket_spec dims_duration_buckets;
extern const dims_bucket_spec dims_byte_buckets;
extern const dims_bucket_spec dims_frame_buckets;

/* One per child. A child writes only the slot it claimed. */
typedef struct {
    apr_uint64_t pid;
    apr_uint64_t resident_bytes;
    apr_uint64_t virtual_bytes;
    apr_uint64_t imagemagick_resource[4];
} dims_process_rec;

typedef struct {
    apr_uint64_t requests[DIMS_ENDPOINT_COUNT][DIMS_OUTCOME_COUNT];
    apr_uint64_t responses[DIMS_ENDPOINT_COUNT][DIMS_CODE_COUNT];
    apr_uint64_t in_flight[DIMS_ENDPOINT_COUNT];
    apr_uint64_t origin_responses[DIMS_ORIGIN_CODE_COUNT];
    apr_uint64_t source_format[DIMS_FORMAT_COUNT];
    apr_uint64_t output_format[DIMS_FORMAT_COUNT];
    apr_uint64_t source_bytes_total;
    apr_uint64_t output_bytes_total;

    apr_uint64_t fetch_results[DIMS_FETCH_RESULT_COUNT];
    apr_uint64_t fetch_errors[DIMS_CURL_CODE_COUNT];
    apr_uint64_t netguard[DIMS_NET_REASON_COUNT];
    apr_uint64_t allowlist[3][2];
    apr_uint64_t signature[DIMS_ENDPOINT_COUNT][DIMS_SIG_RESULT_COUNT];
    apr_uint64_t eurl[2];
    apr_uint64_t operations[DIMS_OP_COUNT][2];
    apr_uint64_t operation_failures[DIMS_OP_COUNT];
    apr_uint64_t exceptions[DIMS_EXC_KIND_COUNT][DIMS_EXC_SEVERITY_COUNT];
    apr_uint64_t overlay_lookups[3];
    apr_uint64_t overlay_evictions;
    apr_uint64_t error_images[3];
    apr_uint64_t error_image_failures;

    dims_histogram_rec request_duration[DIMS_ENDPOINT_COUNT];
    dims_histogram_rec download_duration;
    dims_histogram_rec imagemagick_duration;
    dims_histogram_rec source_bytes;
    dims_histogram_rec output_bytes;
    dims_histogram_rec source_frames;
    dims_histogram_rec operation_duration[DIMS_OP_COUNT];

    /* The slot count comes from AP_MPMQ_HARD_LIMIT_DAEMONS. */
    apr_uint32_t process_slots;
    dims_process_rec process[];
} dims_metrics_rec;

extern dims_metrics_rec *dims_metrics;

/* Creates the block. Runs from dims_init, after apr_atomic_init. */
apr_status_t dims_metrics_init(apr_pool_t *p, server_rec *s);

/* Claims a process slot. Runs from dims_child_init. */
void dims_metrics_child_init(void);

/* The slot this child claimed, or NULL before it claimed one. */
dims_process_rec *dims_metrics_process(void);

/*
 * Index lookups. Each returns a slot in the matching table, and the last slot
 * for a value outside the list.
 */
int dims_metrics_outcome_index(int status);
int dims_metrics_code_index(int code);
int dims_metrics_origin_code_index(int code);
int dims_metrics_format_index(const char *format);
int dims_metrics_curl_code_index(int code);
int dims_metrics_operation_index(const char *operation);
void dims_metrics_exception_slot(int exception_type, int *kind, int *severity);

/* The names the exposition writer prints for each index. */
const char *dims_metrics_endpoint_name(int index);
const char *dims_metrics_outcome_name(int index);
const char *dims_metrics_code_name(int index);
const char *dims_metrics_origin_code_name(int index);
const char *dims_metrics_format_name(int index);
const char *dims_metrics_curl_code_name(int index);
const char *dims_metrics_operation_name(int index);
const char *dims_metrics_exception_kind_name(int index);
const char *dims_metrics_exception_severity_name(int index);
const char *dims_metrics_fetch_result_name(int index);
const char *dims_metrics_net_reason_name(int index);
const char *dims_metrics_sig_result_name(int index);

/* The bucket a value belongs in, counting the +Inf bucket as spec->bounds. */
int dims_metrics_bucket_index(const dims_bucket_spec *spec, double value);

/* Adds one observation. value is microseconds, bytes, or frames. */
void dims_metrics_observe(dims_histogram_rec *h, const dims_bucket_spec *spec,
                          apr_uint64_t value);

/* Why a source fetch ended, as a slot in the fetch table. */
typedef enum {
    DIMS_FETCH_OK = 0,
    DIMS_FETCH_TIMEOUT,
    DIMS_FETCH_TRANSPORT_ERROR,
    DIMS_FETCH_REFUSED,
    DIMS_FETCH_HTTP_ERROR
} dims_fetch_result;

/* Counts one source fetch. curl_code counts too when the result is an error. */
void dims_metrics_fetch(dims_fetch_result result, int curl_code);

/* How a signature check ended, as a slot in the signature table. */
typedef enum {
    DIMS_SIG_OK = 0,
    DIMS_SIG_MISMATCH,
    DIMS_SIG_EXPIRED,
    DIMS_SIG_TOO_FAR_FUTURE,
    DIMS_SIG_MISSING_KEY,
    DIMS_SIG_BAD_CLIENT
} dims_sig_result;

/* Counts one signature check. */
void dims_metrics_signature(int endpoint, dims_sig_result result);

/* Counts one eurl decryption. ok is nonzero when it succeeded. */
void dims_metrics_eurl(int ok);

/* Counts one network guard result, from a dims_net_result. */
void dims_metrics_netguard(int reason);

/* Counts one allowlist check under a dims_allowlist_mode. */
void dims_metrics_allowlist(int mode, int allowed);

/* Counts one operation call and its duration. */
void dims_metrics_operation(int op_index, int from_default, apr_time_t began,
                            int failed);

/* Counts one ImageMagick exception, from an ExceptionType. */
void dims_metrics_exception(int exception_type);

/* Counts one overlay cache lookup. result is a slot: hit, miss, expired. */
void dims_metrics_overlay_lookup(int result);

/*
 * Counts one error image. source is 0 for a drawn image, 1 for a fetched one,
 * and 2 for a server with neither. failed is nonzero when the error image
 * itself failed.
 */
void dims_metrics_error_image(int source, int failed);

/* Counts one overlay cache eviction. */
void dims_metrics_overlay_eviction(void);

/*
 * Counts a request and records its duration when it ends. Registers a pool
 * cleanup, so every return path in the handler reaches it exactly once.
 */
void dims_metrics_request_begin(dims_request_rec *d);

/*
 * Writes this child ImageMagick resource use and process memory into its slot.
 * Runs at the end of a request, so a scrape reports what the last request
 * left.
 */
void dims_metrics_sample_process(void);

/* Answers a location that sets the dims-metrics handler. */
apr_status_t dims_metrics_handler(request_rec *r);

#endif
