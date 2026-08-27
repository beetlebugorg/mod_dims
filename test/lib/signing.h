/*
 * Produces a signed /dims4/ URL for the test secret.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_SIGNING_H
#define DIMS_TEST_SIGNING_H

#include <stddef.h>

/* The client id and the secret in test/conf/dims-test.conf. */
#define DIMS_TEST_CLIENT "TEST"
#define DIMS_TEST_SECRET "t3stk3y"

/* A fixed expiry far enough ahead that the suite never ages out. The value is
 * part of every signature, so it must not be computed from the clock. */
#define DIMS_TEST_EXPIRES "2147483647"

/*
 * Builds a signed /dims4/ path.
 *
 * commands is the command string with no leading or trailing slash, for
 * example "resize/100x50". image_url is the raw source URL.
 *
 * extra is the query string appended after url=, with no leading ampersand,
 * or NULL. keys is the value of _keys, or NULL. mod_dims concatenates the
 * value of each parameter _keys names, in _keys order, so the caller states
 * that order here.
 *
 * The caller frees the result.
 */
char *dims_sign_dims4(const char *commands, const char *image_url,
                      const char *extra, const char *keys);

/* The same, with the signature replaced by the caller's value. Used by the
 * cases that assert a wrong signature is refused. */
char *dims_sign_dims4_with(const char *signature, const char *expires,
                           const char *commands, const char *image_url,
                           const char *extra, const char *keys);

/* The six hexadecimal characters mod_dims compares. The caller frees. */
char *dims_signature_dims4(const char *expires, const char *secret,
                           const char *commands, const char *image_url,
                           const char *const *extra_values, size_t extra_count);

#endif
