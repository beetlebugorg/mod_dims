/*
 * Signing and encrypting a soak request.
 *
 * Every function here reproduces what the module checks. A change to the
 * module's rules that this file does not follow appears in a run as a signed
 * request the service refuses.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "soak.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The salt src/encryption.c derives with. */
static const unsigned char dims_kdf_salt[] = "go-dims";

static int
is_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.' || c == '~';
}

static char *
escape(const char *value, int keep_slash)
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
        if (is_unreserved(*in) || (keep_slash && *in == '/')) {
            *at++ = (char) *in;
        } else if (*in == ' ' && !keep_slash) {
            *at++ = '+';
        } else {
            *at++ = '%';
            *at++ = hex[*in >> 4];
            *at++ = hex[*in & 0x0F];
        }
    }

    *at = '\0';

    return out;
}

char *
dims_escape(const char *value)
{
    return escape(value, 0);
}

char *
dims_escape_path(const char *value)
{
    return escape(value, 1);
}

static char *
to_hex(const unsigned char *bytes, unsigned int length)
{
    static const char hex[] = "0123456789abcdef";
    char *out = malloc((size_t) length * 2 + 1);
    unsigned int i;

    if (out == NULL) {
        return NULL;
    }

    for (i = 0; i < length; i++) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 0x0F];
    }
    out[length * 2] = '\0';

    return out;
}

char *
dims_md5_hex(const char *message)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    if (context == NULL) {
        return NULL;
    }

    if (EVP_DigestInit_ex(context, EVP_md5(), NULL) != 1 ||
            EVP_DigestUpdate(context, message, strlen(message)) != 1 ||
            EVP_DigestFinal_ex(context, digest, &length) != 1) {
        EVP_MD_CTX_free(context);
        return NULL;
    }

    EVP_MD_CTX_free(context);

    return to_hex(digest, length);
}

char *
dims_hmac_sha256_hex(const char *key, const char *message)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    if (HMAC(EVP_sha256(), key, (int) strlen(key),
             (const unsigned char *) message, strlen(message),
             digest, &length) == NULL) {
        return NULL;
    }

    return to_hex(digest, length);
}

int
dims_key_hkdf(const char *secret, unsigned char key[16])
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *context;
    OSSL_PARAM params[5];
    OSSL_PARAM *at = params;
    int ok;

    if (secret == NULL) {
        return 0;
    }

    if (strncmp(secret, "hkdf:", 5) == 0) {
        secret += 5;
    }

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        return 0;
    }

    context = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (context == NULL) {
        return 0;
    }

    *at++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char *) "SHA256", 0);
    *at++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            (void *) (uintptr_t) secret, strlen(secret));
    *at++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
            (void *) (uintptr_t) dims_kdf_salt, sizeof(dims_kdf_salt) - 1);
    *at++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
            (void *) (uintptr_t) "", 0);
    *at = OSSL_PARAM_construct_end();

    ok = EVP_KDF_derive(context, key, 16, params) > 0;
    EVP_KDF_CTX_free(context);

    return ok;
}

int
dims_key_sha1(const char *secret, unsigned char key[16])
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    char *hex;
    int i;

    if (secret == NULL) {
        return 0;
    }

    SHA1((const unsigned char *) secret, strlen(secret), digest);

    hex = to_hex(digest, SHA_DIGEST_LENGTH);
    if (hex == NULL) {
        return 0;
    }

    for (i = 0; i < 16; i++) {
        char c = hex[i];

        key[i] = (unsigned char) ((c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c);
    }

    free(hex);

    return 1;
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
    EVP_CIPHER_CTX *context;
    unsigned char *buffer;
    int url_length = (int) strlen(url);
    int written = 0;
    int final = 0;
    char *encoded;

    /* PKCS5 padding adds up to one whole block. */
    buffer = malloc((size_t) url_length + 16);
    if (buffer == NULL) {
        return NULL;
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        free(buffer);
        return NULL;
    }

    if (EVP_EncryptInit_ex(context, EVP_aes_128_ecb(), NULL, key, NULL) != 1 ||
            EVP_EncryptUpdate(context, buffer, &written,
                    (const unsigned char *) url, url_length) != 1 ||
            EVP_EncryptFinal_ex(context, buffer + written, &final) != 1) {
        EVP_CIPHER_CTX_free(context);
        free(buffer);
        return NULL;
    }

    EVP_CIPHER_CTX_free(context);

    encoded = base64(buffer, written + final);
    free(buffer);

    return encoded;
}
