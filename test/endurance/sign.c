/*
 * Signing and encrypting a soak request.
 *
 * The signature, the key derivation, and the ECB encryption come from
 * libmoddims_sign. The module compiles the same source.
 *
 * The GCM encryption stays here, because the IV comes from the run's seed and
 * a seed reproduces a run.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "soak.h"

#include <dims_sign.h>

#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *
dims_escape(const char *value)
{
    char *out = NULL;

    if (value == NULL || dims_sign_escape(value, &out) != DIMS_SIGN_OK) {
        return NULL;
    }

    /* The soak links the static library, so free releases this. */
    return out;
}

/*
 * A path escape, which the library does not offer. A slash separates the
 * commands, so it passes through, and a space travels as %20 rather than as a
 * plus.
 */
char *
dims_escape_path(const char *value)
{
    static const char hex[] = "0123456789ABCDEF";
    const unsigned char *in;
    char *out;
    char *at;

    if (value == NULL) {
        return NULL;
    }

    out = malloc(strlen(value) * 3 + 1);
    if (out == NULL) {
        return NULL;
    }
    at = out;

    for (in = (const unsigned char *) value; *in != '\0'; in++) {
        if ((*in >= 'A' && *in <= 'Z') || (*in >= 'a' && *in <= 'z') ||
                (*in >= '0' && *in <= '9') || *in == '-' || *in == '_' ||
                *in == '.' || *in == '~' || *in == '/') {
            *at++ = (char) *in;
        } else {
            *at++ = '%';
            *at++ = hex[*in >> 4];
            *at++ = hex[*in & 0x0F];
        }
    }

    *at = '\0';

    return out;
}


int
dims_key_hkdf(const char *secret, unsigned char key[16])
{
    return dims_sign_derive_key(secret, key) == DIMS_SIGN_OK;
}

int
dims_key_sha1(const char *secret, unsigned char key[16])
{
    char prefixed[256];

    if (secret == NULL || strlen(secret) + 6 > sizeof(prefixed)) {
        return 0;
    }

    snprintf(prefixed, sizeof(prefixed), "sha1:%s", secret);

    return dims_sign_derive_key(prefixed, key) == DIMS_SIGN_OK;
}

/* Base64 without line breaks. The caller frees. */
static char *
base64(const unsigned char *bytes, int length)
{
    char *out = malloc((size_t) (length + 2) / 3 * 4 + 1);
    int written;

    if (out == NULL) {
        return NULL;
    }

    written = EVP_EncodeBlock((unsigned char *) out, bytes, length);
    if (written < 0) {
        free(out);
        return NULL;
    }
    out[written] = '\0';

    return out;
}

char *
dims_eurl_gcm(const unsigned char key[16], const char *url, dims_rng *rng)
{
    EVP_CIPHER_CTX *context;
    unsigned char *buffer;
    unsigned char *iv;
    unsigned char *ciphertext;
    unsigned char *tag;
    int url_length = (int) strlen(url);
    int total = 12 + url_length + 16;
    int written = 0;
    int final = 0;
    int i;
    char *encoded;

    buffer = malloc((size_t) total);
    if (buffer == NULL) {
        return NULL;
    }

    iv = buffer;
    ciphertext = buffer + 12;
    tag = buffer + 12 + url_length;

    for (i = 0; i < 12; i++) {
        iv[i] = (unsigned char) dims_rng_below(rng, 256);
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        free(buffer);
        return NULL;
    }

    if (EVP_EncryptInit_ex(context, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
            EVP_EncryptInit_ex(context, NULL, NULL, key, iv) != 1 ||
            EVP_EncryptUpdate(context, ciphertext, &written,
                    (const unsigned char *) url, url_length) != 1 ||
            EVP_EncryptFinal_ex(context, ciphertext + written, &final) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(context);
        free(buffer);
        return NULL;
    }

    EVP_CIPHER_CTX_free(context);

    encoded = base64(buffer, total);
    free(buffer);

    return encoded;
}

char *
dims_eurl_ecb(const unsigned char key[16], const char *url)
{
    char *out = NULL;

    if (dims_sign_eurl_encrypt(url, key, DIMS_SIGN_EURL_ECB, &out) !=
            DIMS_SIGN_OK) {
        return NULL;
    }

    return out;
}

