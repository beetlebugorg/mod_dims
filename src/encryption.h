/*
 * Decrypting the eurl request parameter.
 *
 * eurl is an encrypted source URL, so a signed URL can hide where the
 * image really comes from. The key is derived from the client's secret.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_ENCRYPTION_H
#define _DIMS_ENCRYPTION_H

#include "mod_dims.h"

/* The shortest thing AES-128-ECB can decrypt. */
#define DIMS_AES_BLOCK_BYTES 16

/* What the GCM input has before and after the ciphertext. */
#define DIMS_GCM_IV_BYTES 12
#define DIMS_GCM_TAG_BYTES 16

/* Reports an OpenSSL error through the request log. Passed to
 * ERR_print_errors_cb. */
int aes_errors(const char *message, size_t length, void *u);

/* AES-128-ECB with PKCS5 padding. The default, and the weaker of the two:
 * ECB has no integrity check and no IV. */
char *aes_128_decrypt(request_rec *r, unsigned char *key,
                      unsigned char *encrypted_text, int encrypted_length);

/* AES-128-GCM. The base64 input has the IV, the ciphertext, and the tag,
 * in that order. */
char *aes_128_gcm_decrypt(request_rec *r, unsigned char *key,
                          unsigned char *base64_encrypted_text);

/* The AES key length both schemes use. */
#define DIMS_AES_KEY_BYTES 16

/*
 * Derives the AES key from a secret.
 *
 * A secret with a sha1: prefix takes the older path: SHA-1 of the rest, hex
 * encoded, the first 16 characters uppercased. That is 64 bits of material
 * spread across 16 bytes.
 *
 * Anything else takes HKDF-SHA256, with a hkdf: prefix stripped first.
 *
 * key must have room for DIMS_AES_KEY_BYTES.
 */
int dims_derive_key(const char *secret, unsigned char *key);

#endif
