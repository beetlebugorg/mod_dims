/*
 * The /dims5/ signature, over an APR pool.
 *
 * The rules are in sign/, so the module and the clients state them once.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_SIGNATURE_H
#define _DIMS_SIGNATURE_H

#include "mod_dims.h"

/*
 * The signature for one request, hex encoded, from the pool. NULL when the
 * library refuses the input.
 *
 * commands and image_url are already decoded. query is the raw query string,
 * and this builds the canonical form of it.
 */
char *dims_signature(apr_pool_t *pool, const char *key, const char *commands,
                     const char *image_url, const char *query);

/*
 * Whether two signatures match, comparing every byte whatever the answer.
 *
 * A comparison that stops at the first difference reports how many leading
 * characters were right.
 */
int dims_signature_equal(const char *a, const char *b);

/*
 * Whether a field the signature covers holds a control character.
 *
 * The message puts one field per line, so a field holding a line break could
 * stand in for two.
 */
int dims_signature_field_ok(const char *field);

#endif
