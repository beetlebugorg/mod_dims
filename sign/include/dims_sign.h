/*
 * The mod_dims signing rules.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_SIGN_H
#define DIMS_SIGN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The hex MD5 a /dims4/ signature comes from. */
#define DIMS_SIGN_DIMS4_DIGEST 32

/*
 * How many characters of that digest a /dims4/ path holds. The module compares
 * six, and every /dims4/ URL has held six. A caller asks for more with a
 * longer placeholder, up to the whole digest.
 */
#define DIMS_SIGN_DIMS4_LENGTH 6

/* A /dims5/ signature: a hex HMAC-SHA256. */
#define DIMS_SIGN_DIMS5_LENGTH 64

/* The prefix each endpoint conventionally serves at. */
#define DIMS_SIGN_DIMS4_PREFIX "/dims4/"
#define DIMS_SIGN_DIMS5_PREFIX "/dims5/"

/* The AES key both eurl schemes use. */
#define DIMS_SIGN_KEY_BYTES 16

/* One AES block, which is the shortest thing ECB can decrypt. */
#define DIMS_SIGN_AES_BLOCK_BYTES 16

/* What a GCM value has before and after the ciphertext. */
#define DIMS_SIGN_GCM_IV_BYTES 12
#define DIMS_SIGN_GCM_TAG_BYTES 16

typedef enum {
    DIMS_SIGN_OK = 0,
    DIMS_SIGN_MEMORY,       /* malloc refused */
    DIMS_SIGN_BAD_ARGUMENT, /* a required argument is NULL or empty */
    DIMS_SIGN_BAD_URL,      /* the path does not start with the prefix, a
                               percent escape is not two hex digits, a
                               /dims4/ path has fewer than four segments after
                               the prefix, a /dims4/ expiry is not decimal
                               digits, a /dims4/ signature segment is shorter
                               than DIMS_SIGN_DIMS4_LENGTH, or the query has
                               no url */
    DIMS_SIGN_BAD_FIELD,    /* a signed field holds a control character */
    DIMS_SIGN_CRYPTO,       /* libcrypto refused */
    DIMS_SIGN_BAD_EURL      /* an eurl value is not base64, is too short for
                               its scheme, or fails its tag check */
} dims_sign_status;

/* Which cipher an eurl value uses. */
typedef enum {
    /* AES-128-GCM. What /dims5/ reads, and what /dims4/ reads under
       DimsEncryptionAlgorithm AES/GCM/NoPadding. */
    DIMS_SIGN_EURL_GCM = 0,

    /* AES-128-ECB with PKCS5 padding. The /dims4/ default. It has no
       integrity check and no IV. */
    DIMS_SIGN_EURL_ECB
} dims_sign_cipher;

/* A short description of a status, for an error message. */
const char *dims_sign_strerror(dims_sign_status status);

/*
 * Releases a string one of the functions below wrote.
 *
 * Use this and not free. A shared library build allocates from its own heap,
 * and on Windows that is not the heap the caller frees from.
 */
void dims_sign_free(char *string);

/*
 * Signs one /dims5/ URL under one key.
 *
 * url is absolute or a path. prefix is what comes before the commands in that
 * path, and NULL means DIMS_SIGN_DIMS5_PREFIX. The signature covers everything
 * between the prefix and the query, percent decoded, so a caller behind a
 * rewrite passes the public prefix and gets the signature the module computes
 * after the rewrite.
 *
 * The query passes through as it is. This function reads it and does not
 * rewrite it. sig goes on the end, and an input that already holds one gets a
 * new one in its place.
 *
 * On DIMS_SIGN_OK, *out holds the signed URL. Release it with dims_sign_free.
 */
dims_sign_status dims_sign_dims5_url(const char *url, const char *key,
                                     const char *prefix, char **out);

/*
 * Signs one /dims4/ URL under one client secret.
 *
 * prefix is what comes before the client id, and NULL means
 * DIMS_SIGN_DIMS4_PREFIX. Four segments follow it: the client id, the
 * signature, the expiry, and the commands.
 *
 * The length of the placeholder in the signature segment sets the length of
 * the signature, from DIMS_SIGN_DIMS4_LENGTH to DIMS_SIGN_DIMS4_DIGEST
 * characters.
 *
 * The image URL signs with every plus written as a space. The module applies
 * that rule on this endpoint. /dims5/ keeps the plus.
 *
 * On DIMS_SIGN_OK, *out holds the signed URL. Release it with dims_sign_free.
 */
dims_sign_status dims_sign_dims4_url(const char *url, const char *key,
                                     const char *prefix, char **out);

/*
 * Builds the message dims_sign_dims5_url hashes, so a caller can read what a
 * server disagreed with. It hashes nothing itself.
 *
 * The message is the commands, the image URL, and the canonical query,
 * separated by newlines:
 *
 *     resize/100x100/
 *     http://origin:8080/grid.png
 *     overlay=http%3A%2F%2Forigin%3A8080%2Foverlay.png
 *
 * There is no /dims4/ version. A /dims4/ message contains the client secret.
 *
 * On DIMS_SIGN_OK, *out holds the message. Release it with dims_sign_free.
 */
dims_sign_status dims_sign_dims5_message(const char *url, const char *prefix,
                                         char **out);

/*
 * Signs one /dims5/ URL and encrypts its image URL.
 *
 * The signature covers the plaintext image URL, so the server verifies the
 * request after it decrypts. The output holds eurl in place of url, percent
 * encoded, because the module decodes that parameter.
 *
 * key is the DimsSigningKey. This derives the AES key from it.
 *
 * On DIMS_SIGN_OK, *out holds the signed URL. Release it with dims_sign_free.
 */
dims_sign_status dims_sign_dims5_eurl_url(const char *url, const char *key,
                                          const char *prefix, char **out);

/*
 * Signs one /dims4/ URL and encrypts its image URL.
 *
 * The output holds eurl in place of url, undecoded, because the module reads
 * that parameter as it appears in the query.
 *
 * cipher names the scheme the server is configured for. This endpoint reads
 * one derivation whatever the secret looks like, so the AES key comes from
 * SHA-1 of the client secret.
 *
 * On DIMS_SIGN_OK, *out holds the signed URL. Release it with dims_sign_free.
 */
dims_sign_status dims_sign_dims4_eurl_url(const char *url, const char *key,
                                          const char *prefix,
                                          dims_sign_cipher cipher, char **out);

/* -- The rules, for the module and the command -- */

/*
 * Derives the AES key an eurl value uses.
 *
 * A secret with a sha1: prefix takes the older path: SHA-1 of the rest, hex
 * encoded, the first 16 characters uppercased. That is 64 bits of material
 * spread across 16 bytes. Anything else takes HKDF-SHA256, with a hkdf:
 * prefix stripped first.
 *
 * /dims4/ reads the older path whatever the secret looks like, so a /dims4/
 * caller writes sha1: in front of the client secret.
 */
dims_sign_status dims_sign_derive_key(const char *secret,
                                      unsigned char key[DIMS_SIGN_KEY_BYTES]);

/*
 * Encrypts one image URL for the eurl parameter.
 *
 * A GCM value is the 12 byte IV, the ciphertext, and the 16 byte tag, base64
 * encoded. The IV comes from the system random source, so two calls on one
 * URL under one key produce two values.
 *
 * An ECB value is the ciphertext alone, base64 encoded.
 *
 * On DIMS_SIGN_OK, *out holds the value. Release it with dims_sign_free.
 */
dims_sign_status dims_sign_eurl_encrypt(const char *image_url,
                                        const unsigned char key[DIMS_SIGN_KEY_BYTES],
                                        dims_sign_cipher cipher, char **out);

/*
 * Decrypts one eurl value, so a caller reads back what it wrote.
 *
 * Returns DIMS_SIGN_BAD_EURL when the value is not base64, is too short for
 * its scheme, or fails its tag check.
 *
 * On DIMS_SIGN_OK, *out holds the image URL. Release it with dims_sign_free.
 */
dims_sign_status dims_sign_eurl_decrypt(const char *eurl,
                                        const unsigned char key[DIMS_SIGN_KEY_BYTES],
                                        dims_sign_cipher cipher, char **out);

/*
 * Percent encodes one query component.
 *
 * Everything outside A-Za-z0-9-_.~ becomes %XX with uppercase hex, and a space
 * becomes a plus.
 *
 * On DIMS_SIGN_OK, *out holds the escaped value. Release it with
 * dims_sign_free.
 */
dims_sign_status dims_sign_escape(const char *value, char **out);

/*
 * Builds the canonical query, which is the third line of a /dims5/ message.
 *
 * Each parameter is decoded, with a plus read as a space, then written
 * name=value and percent encoded. The parameters are ordered by the bytes of
 * the name. A name that appears more than once keeps the order the query
 * gives. A parameter with no equals sign has an empty value.
 *
 * sig, url, eurl, _keys, and download take no part and are left out.
 *
 * On DIMS_SIGN_OK, *out holds the canonical query. Release it with
 * dims_sign_free.
 */
dims_sign_status dims_sign_canonical_query(const char *query, char **out);

/*
 * Hashes the commands, the image URL, and the canonical query under the key,
 * and writes the digest as 64 lowercase hex characters.
 *
 * The commands go in as given. The module signs what follows the prefix in
 * the decoded r->uri, trailing slash or not, so a verifier passes those bytes
 * and adds nothing.
 *
 * Returns DIMS_SIGN_BAD_FIELD when the commands or the image URL hold a
 * control character. See dims_sign_field_ok.
 */
dims_sign_status dims_sign_dims5_digest(const char *key, const char *commands,
                                        const char *image_url,
                                        const char *canonical_query,
                                        char out[DIMS_SIGN_DIMS5_LENGTH + 1]);

/* One name and one value, for a /dims4/ signature. */
typedef struct {
    const char *name;
    const char *value;
} dims_sign_param;

/*
 * Hashes the expiry, the secret, the commands, the image URL, and the value of
 * each named parameter, joined with nothing between them, and writes the MD5
 * as 32 lowercase hex characters.
 *
 * The commands go in as given, with a space already written as a plus. Each
 * value goes in as it appears in the query, not decoded. A parameter with a
 * NULL value contributes nothing and does not stop the ones after it, which is
 * what the module does when _keys names a parameter the request leaves out.
 *
 * out holds the whole digest. The URL takes the first
 * DIMS_SIGN_DIMS4_LENGTH characters, or more when the caller asks for more.
 */
dims_sign_status dims_sign_dims4_digest(const char *secret,
                                        const char *expires,
                                        const char *commands,
                                        const char *image_url,
                                        const dims_sign_param *keys,
                                        size_t key_count,
                                        char out[DIMS_SIGN_DIMS4_DIGEST + 1]);

/*
 * Reports whether a /dims5/ signature matches the expected digest. Returns 1
 * when both are exactly DIMS_SIGN_DIMS5_LENGTH characters and equal, case
 * sensitively.
 *
 * The comparison reads every byte whatever the answer. One that stops at the
 * first difference reports how many leading characters were right.
 */
int dims_sign_dims5_equal(const char *expected, const char *given);

/*
 * Reports whether a /dims4/ signature matches the expected digest. Returns 1
 * when the first DIMS_SIGN_DIMS4_LENGTH characters agree without regard to
 * case. given may be longer, and the rest is not read.
 *
 * The comparison reads every one of those bytes whatever the answer.
 */
int dims_sign_dims4_equal(const char *expected, const char *given);

/*
 * Reports whether a field is safe to put in a /dims5/ message. Returns 1 when
 * the field holds no control character.
 *
 * The message puts one field per line, so a field holding a newline could stand
 * in for two.
 */
int dims_sign_field_ok(const char *field);

#ifdef __cplusplus
}
#endif

#endif
