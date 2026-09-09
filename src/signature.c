/*
 * The /dims5/ signature, over an APR pool.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "signature.h"

#include <dims_sign.h>

char *
dims_signature(apr_pool_t *pool, const char *key, const char *commands,
               const char *image_url, const char *query)
{
    char digest[DIMS_SIGN_DIMS5_LENGTH + 1];
    char *canonical;
    dims_sign_status status;

    if (dims_sign_canonical_query(query, &canonical) != DIMS_SIGN_OK) {
        return NULL;
    }

    status = dims_sign_dims5_digest(key, commands, image_url, canonical,
                                    digest);
    dims_sign_free(canonical);

    return (status == DIMS_SIGN_OK) ? apr_pstrdup(pool, digest) : NULL;
}

int
dims_signature_equal(const char *a, const char *b)
{
    return dims_sign_dims5_equal(a, b);
}

int
dims_signature_field_ok(const char *field)
{
    return dims_sign_field_ok(field);
}
