/*
 * Decrypting the eurl request parameter.
 *
 * eurl carries an encrypted source URL, so a signed URL can hide where the
 * image really comes from. The key is derived from the client's secret.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_ENCRYPTION_H
#define _DIMS_ENCRYPTION_H

#include "mod_dims.h"

/* Reports an OpenSSL error through the request log. Passed to
 * ERR_print_errors_cb. */
int aes_errors(const char *message, size_t length, void *u);

/* AES-128-ECB with PKCS5 padding. The default, and the weaker of the two:
 * ECB has no integrity check and no IV. */
char *aes_128_decrypt(request_rec *r, unsigned char *key,
                      unsigned char *encrypted_text, int encrypted_length);

/* AES-128-GCM. The base64 input carries the IV, the ciphertext, and the tag,
 * in that order. */
char *aes_128_gcm_decrypt(request_rec *r, unsigned char *key,
                          unsigned char *base64_encrypted_text);

#endif
