/*
 * The /dims5/ signature.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_SIGNATURE_H
#define _DIMS_SIGNATURE_H

#include "mod_dims.h"

/* An HMAC-SHA256 digest, hex encoded. */
#define DIMS_SIGNATURE_LENGTH 64

/*
 * Percent encodes one query component.
 *
 * Everything outside A-Za-z0-9-_.~ is escaped as %XX with uppercase hex, and
 * a space becomes a plus.
 */
char *dims_query_escape(apr_pool_t *pool, const char *value);

/*
 * The canonical form of every query parameter the signature covers.
 *
 * Each parameter is written name=value, percent encoded, and the whole is
 * ordered by name. A parameter with several values contributes each of them,
 * in the order the query gives.
 *
 * sig, url, eurl, _keys, and download take no part and are left out.
 */
char *dims_signed_query(apr_pool_t *pool, const char *query);

/*
 * The message a signature covers: the commands, the image URL, and the
 * canonical query, one per line.
 */
char *dims_signature_message(apr_pool_t *pool, const char *commands,
                             const char *image_url, const char *signed_query);

/* HMAC-SHA256 of message under key, hex encoded and lowercase. */
char *dims_signature_compute(apr_pool_t *pool, const char *key,
                             const char *message);

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
