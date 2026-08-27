/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operation.h"

#include <stdio.h>
#include <string.h>

/* "grid.png" becomes "grid". */
static void
fixture_stem(const char *image, char *out, size_t out_len)
{
    const char *dot = strrchr(image, '.');
    size_t len = (dot != NULL) ? (size_t) (dot - image) : strlen(image);

    if (len >= out_len) {
        len = out_len - 1;
    }

    memcpy(out, image, len);
    out[len] = '\0';
}

void
dims_run_operation_with_query(const char *name, const char *image,
                              dims_operation_func *operation, const char *args,
                              const char *query, long want_width, long want_height)
{
    dims_request_rec *d = dims_fixture_request(image, query);
    const char *error = NULL;
    apr_status_t code;
    unsigned char *blob;
    size_t length = 0;
    char stem[128];
    char golden_name[256];
    long width, height;

    if (d == NULL) {
        return;
    }

    /* The module hands the operation a writable copy, and several operations
     * edit their argument in place. */
    code = operation(d, args ? apr_pstrdup(d->pool, args) : NULL, &error);
    if (code != DIMS_SUCCESS) {
        FAIL("%s(%s) failed: %s", name, args ? args : "(none)",
             error ? error : "no message");
        dims_fixture_free(d);
        return;
    }

    width = (long) MagickGetImageWidth(d->wand);
    height = (long) MagickGetImageHeight(d->wand);

    if (want_width < 0 && want_height < 0) {
        dims_test_logf("%s: %ldx%ld", name, width, height);
    }
    if (want_width >= 0) {
        CHECK_INT(width, want_width, "width");
    }
    if (want_height >= 0) {
        CHECK_INT(height, want_height, "height");
    }

    blob = dims_fixture_export(d, &length);

    fixture_stem(image, stem, sizeof(stem));
    snprintf(golden_name, sizeof(golden_name), "unit.%s.%s", stem, name);

    assert_golden(golden_name, blob, length, dims_fixture_extension(d));

    MagickRelinquishMemory(blob);
    dims_fixture_free(d);
}

void
dims_run_operation(const char *name, const char *image, dims_operation_func *operation,
                   const char *args, long want_width, long want_height)
{
    dims_run_operation_with_query(name, image, operation, args, NULL, want_width,
                                  want_height);
}

apr_status_t
dims_operation_status(const char *image, dims_operation_func *operation, const char *args)
{
    dims_request_rec *d = dims_fixture_request(image, NULL);
    const char *error = NULL;
    apr_status_t code;

    if (d == NULL) {
        return DIMS_FAILURE;
    }

    code = operation(d, args ? apr_pstrdup(d->pool, args) : NULL, &error);
    dims_fixture_free(d);

    return code;
}

apr_status_t
dims_operation_status_with_query(const char *image, dims_operation_func *operation,
                                 const char *args, const char *query)
{
    dims_request_rec *d = dims_fixture_request(image, query);
    const char *error = NULL;
    apr_status_t code;

    if (d == NULL) {
        return DIMS_FAILURE;
    }

    code = operation(d, args ? apr_pstrdup(d->pool, args) : NULL, &error);
    dims_fixture_free(d);

    return code;
}
