/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/test.h"
#include "../../src/metrics.h"

#include <string.h>

/*
 * A bound belongs to its own bucket, because Prometheus buckets are "less than
 * or equal to". A value above the last bound belongs to +Inf, which sits at
 * index bounds.
 */
static void
test_bucket_boundaries(void)
{
    const dims_bucket_spec *spec = &dims_duration_buckets;

    CHECK_INT(dims_metrics_bucket_index(spec, 0.0), 0, "zero");
    CHECK_INT(dims_metrics_bucket_index(spec, 0.005), 0, "the first bound");
    CHECK_INT(dims_metrics_bucket_index(spec, 0.0051), 1, "just above it");
    CHECK_INT(dims_metrics_bucket_index(spec, 10.0), spec->bounds - 1,
              "the last bound");
    CHECK_INT(dims_metrics_bucket_index(spec, 10.1), spec->bounds,
              "above the last bound");
}

static void
test_byte_and_frame_boundaries(void)
{
    CHECK_INT(dims_metrics_bucket_index(&dims_byte_buckets, 16384), 0,
              "16Ki");
    CHECK_INT(dims_metrics_bucket_index(&dims_byte_buckets, 16385), 1,
              "just above 16Ki");
    CHECK_INT(dims_metrics_bucket_index(&dims_byte_buckets, 1 << 30),
              dims_byte_buckets.bounds, "a gigabyte");

    CHECK_INT(dims_metrics_bucket_index(&dims_frame_buckets, 1), 0,
              "one frame");
    CHECK_INT(dims_metrics_bucket_index(&dims_frame_buckets, 3), 2,
              "three frames");
    CHECK_INT(dims_metrics_bucket_index(&dims_frame_buckets, 500),
              dims_frame_buckets.bounds, "five hundred frames");
}

/* Every bucket table fits the record, which the exposition writer walks. */
static void
test_bucket_tables_fit(void)
{
    CHECK(dims_duration_buckets.bounds + 1 <= DIMS_BUCKET_MAX,
          "the duration table fits");
    CHECK(dims_byte_buckets.bounds + 1 <= DIMS_BUCKET_MAX,
          "the byte table fits");
    CHECK(dims_frame_buckets.bounds + 1 <= DIMS_BUCKET_MAX,
          "the frame table fits");
}

/*
 * A bucket holds the observations that fall in it alone. The writer adds them
 * up, so the total across the table equals the count.
 */
static void
test_histogram_totals(void)
{
    dims_histogram_rec h;
    apr_uint64_t total = 0;
    int i;

    memset(&h, 0, sizeof(h));

    /* Three microseconds, half a second, and a minute. */
    dims_metrics_observe(&h, &dims_duration_buckets, 3);
    dims_metrics_observe(&h, &dims_duration_buckets, 500000);
    dims_metrics_observe(&h, &dims_duration_buckets, 60000000);

    CHECK_INT((long) h.count, 3, "the count");
    CHECK_INT((long) h.sum, 60500003, "the sum in microseconds");

    for (i = 0; i < DIMS_BUCKET_MAX; i++) {
        total += h.bucket[i];
    }

    CHECK_INT((long) total, 3, "the buckets add up to the count");
    CHECK_INT((long) h.bucket[0], 1, "three microseconds is the first bucket");
    CHECK_INT((long) h.bucket[dims_duration_buckets.bounds], 1,
              "a minute is the +Inf bucket");
}

/* A byte observation reports bytes, with no division. */
static void
test_histogram_counts_bytes(void)
{
    dims_histogram_rec h;

    memset(&h, 0, sizeof(h));

    dims_metrics_observe(&h, &dims_byte_buckets, 2048);

    CHECK_INT((long) h.sum, 2048, "the sum in bytes");
    CHECK_INT((long) h.bucket[0], 1, "two kilobytes is the first bucket");
}

static void
test_outcome_index(void)
{
    CHECK_INT(dims_metrics_outcome_index(DIMS_SUCCESS), 0, "success");
    CHECK_INT(dims_metrics_outcome_index(DIMS_NETWORK_REFUSED),
              DIMS_OUTCOME_COUNT - 1, "the last status");
    CHECK_INT(dims_metrics_outcome_index(DIMS_IGNORE), DIMS_OUTCOME_COUNT - 1,
              "a status outside the table");
    CHECK_STR(dims_metrics_outcome_name(0), "success", "the first name");
}

static void
test_code_index(void)
{
    CHECK_STR(dims_metrics_code_name(dims_metrics_code_index(200)), "200",
              "a listed code");
    CHECK_STR(dims_metrics_code_name(dims_metrics_code_index(504)), "504",
              "the last listed code");
    CHECK_STR(dims_metrics_code_name(dims_metrics_code_index(418)), "other",
              "a code outside the list");
}

/* DimsOriginStatusMode forward reports whatever the origin returned. */
static void
test_origin_code_index(void)
{
    CHECK_STR(dims_metrics_origin_code_name(dims_metrics_origin_code_index(304)),
              "304", "a listed code");
    CHECK_STR(dims_metrics_origin_code_name(dims_metrics_origin_code_index(451)),
              "other", "a code outside the list");
}

static void
test_format_index(void)
{
    CHECK_STR(dims_metrics_format_name(dims_metrics_format_index("PNG")),
              "png", "an upper case format");
    CHECK_STR(dims_metrics_format_name(dims_metrics_format_index("JPG")),
              "jpeg", "JPG names JPEG");
    CHECK_STR(dims_metrics_format_name(dims_metrics_format_index("PCX")),
              "other", "a format outside the list");
    CHECK_STR(dims_metrics_format_name(dims_metrics_format_index(NULL)),
              "other", "no format");
}

const dims_test dims_tests_unit_metrics[] = {
    { "TestBucketBoundaries", test_bucket_boundaries, NULL },
    { "TestByteAndFrameBoundaries", test_byte_and_frame_boundaries, NULL },
    { "TestBucketTablesFit", test_bucket_tables_fit, NULL },
    { "TestHistogramTotals", test_histogram_totals, NULL },
    { "TestHistogramCountsBytes", test_histogram_counts_bytes, NULL },
    { "TestOutcomeIndex", test_outcome_index, NULL },
    { "TestCodeIndex", test_code_index, NULL },
    { "TestOriginCodeIndex", test_origin_code_index, NULL },
    { "TestFormatIndex", test_format_index, NULL },
    DIMS_TEST_END
};
