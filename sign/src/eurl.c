/*
 * The eurl parameter: an image URL encrypted under a key derived from the
 * secret.
 *
 * The module decrypts in src/encryption.c. These are the same rules in the
 * other direction, plus a decrypt so a caller can read back what it wrote.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "dims_sign.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

/* The salt the key derivation uses. Changing it invalidates every eurl. */
static const unsigned char kdf_salt[] = "go-dims";

dims_sign_status
dims_sign_derive_key(const char *secret, unsigned char key[DIMS_SIGN_KEY_BYTES])
{
    static const char hex[] = "0123456789ABCDEF";
    EVP_KDF *kdf;
    EVP_KDF_CTX *context;
    OSSL_PARAM params[5];
    OSSL_PARAM *at = params;
    int ok;

    if (secret == NULL || *secret == '\0' || key == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    /* SHA-1 of the secret, hex encoded, the first sixteen characters
     * uppercased. That is 64 bits of material spread across 16 bytes. */
    if (strncmp(secret, "sha1:", 5) == 0) {
        unsigned char digest[SHA_DIGEST_LENGTH];
        int i;

        secret += 5;
        if (SHA1((const unsigned char *) secret, strlen(secret), digest) == NULL) {
            return DIMS_SIGN_CRYPTO;
        }

        for (i = 0; i < DIMS_SIGN_KEY_BYTES; i++) {
            key[i] = (unsigned char) ((i % 2 == 0)
                    ? hex[digest[i / 2] >> 4]
                    : hex[digest[i / 2] & 0x0F]);
        }

        return DIMS_SIGN_OK;
    }

    if (strncmp(secret, "hkdf:", 5) == 0) {
        secret += 5;
    }

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        return DIMS_SIGN_CRYPTO;
    }

    context = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (context == NULL) {
        return DIMS_SIGN_CRYPTO;
    }

    *at++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char *) "SHA256", 0);
    *at++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            (void *) (uintptr_t) secret, strlen(secret));
    *at++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
            (void *) (uintptr_t) kdf_salt, sizeof(kdf_salt) - 1);
    *at++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
            (void *) (uintptr_t) "", 0);
    *at = OSSL_PARAM_construct_end();

    ok = EVP_KDF_derive(context, key, DIMS_SIGN_KEY_BYTES, params) > 0;
    EVP_KDF_CTX_free(context);

    return ok ? DIMS_SIGN_OK : DIMS_SIGN_CRYPTO;
}

/* -- base64 ------------------------------------------------------------- */

static char *
base64_encode(const unsigned char *bytes, int length)
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

/* Decodes base64 into a fresh buffer. Returns the byte count, or -1. */
static int
base64_decode(const char *text, unsigned char **out)
{
    size_t length = strlen(text);
    unsigned char *bytes;
    int written;
    size_t padding = 0;

    /* EVP_DecodeBlock writes three bytes for every four characters, so the
     * buffer is sized from the input and the count is corrected for the
     * padding the encoder added. */
    if (length == 0 || length % 4 != 0) {
        return -1;
    }

    bytes = malloc(length / 4 * 3 + 1);
    if (bytes == NULL) {
        return -1;
    }

    written = EVP_DecodeBlock(bytes, (const unsigned char *) text, (int) length);
    if (written < 0) {
        free(bytes);
        return -1;
    }

    if (length >= 1 && text[length - 1] == '=') {
        padding++;
    }
    if (length >= 2 && text[length - 2] == '=') {
        padding++;
    }

    written -= (int) padding;
    if (written < 0) {
        free(bytes);
        return -1;
    }

    *out = bytes;

    return written;
}

/* -- Encrypt ------------------------------------------------------------ */

static dims_sign_status
encrypt_gcm(const char *image_url, const unsigned char *key, char **out)
{
    EVP_CIPHER_CTX *context;
    unsigned char *buffer;
    unsigned char *iv;
    unsigned char *ciphertext;
    unsigned char *tag;
    int length = (int) strlen(image_url);
    int total = DIMS_SIGN_GCM_IV_BYTES + length + DIMS_SIGN_GCM_TAG_BYTES;
    int written = 0;
    int final = 0;

    buffer = malloc((size_t) total);
    if (buffer == NULL) {
        return DIMS_SIGN_MEMORY;
    }

    iv = buffer;
    ciphertext = buffer + DIMS_SIGN_GCM_IV_BYTES;
    tag = ciphertext + length;

    /* A fresh IV for every call. Two encryptions of one URL under one key
     * must not produce one value. */
    if (RAND_bytes(iv, DIMS_SIGN_GCM_IV_BYTES) != 1) {
        free(buffer);
        return DIMS_SIGN_CRYPTO;
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        free(buffer);
        return DIMS_SIGN_CRYPTO;
    }

    if (EVP_EncryptInit_ex(context, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                    DIMS_SIGN_GCM_IV_BYTES, NULL) != 1 ||
            EVP_EncryptInit_ex(context, NULL, NULL, key, iv) != 1 ||
            EVP_EncryptUpdate(context, ciphertext, &written,
                    (const unsigned char *) image_url, length) != 1 ||
            EVP_EncryptFinal_ex(context, ciphertext + written, &final) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                    DIMS_SIGN_GCM_TAG_BYTES, tag) != 1) {
        EVP_CIPHER_CTX_free(context);
        free(buffer);
        return DIMS_SIGN_CRYPTO;
    }

    EVP_CIPHER_CTX_free(context);

    *out = base64_encode(buffer, total);
    free(buffer);

    return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
}

static dims_sign_status
encrypt_ecb(const char *image_url, const unsigned char *key, char **out)
{
    EVP_CIPHER_CTX *context;
    unsigned char *buffer;
    int length = (int) strlen(image_url);
    int written = 0;
    int final = 0;

    /* PKCS5 padding adds up to one whole block. */
    buffer = malloc((size_t) length + DIMS_SIGN_AES_BLOCK_BYTES);
    if (buffer == NULL) {
        return DIMS_SIGN_MEMORY;
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        free(buffer);
        return DIMS_SIGN_CRYPTO;
    }

    if (EVP_EncryptInit_ex(context, EVP_aes_128_ecb(), NULL, key, NULL) != 1 ||
            EVP_EncryptUpdate(context, buffer, &written,
                    (const unsigned char *) image_url, length) != 1 ||
            EVP_EncryptFinal_ex(context, buffer + written, &final) != 1) {
        EVP_CIPHER_CTX_free(context);
        free(buffer);
        return DIMS_SIGN_CRYPTO;
    }

    EVP_CIPHER_CTX_free(context);

    *out = base64_encode(buffer, written + final);
    free(buffer);

    return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
}

dims_sign_status
dims_sign_eurl_encrypt(const char *image_url,
                       const unsigned char key[DIMS_SIGN_KEY_BYTES],
                       dims_sign_cipher cipher, char **out)
{
    if (out == NULL || image_url == NULL || key == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    if (cipher == DIMS_SIGN_EURL_ECB) {
        return encrypt_ecb(image_url, key, out);
    }

    return encrypt_gcm(image_url, key, out);
}

/* -- Decrypt ------------------------------------------------------------ */

static dims_sign_status
decrypt_gcm(const unsigned char *bytes, int length, const unsigned char *key,
            char **out)
{
    EVP_CIPHER_CTX *context;
    const unsigned char *iv = bytes;
    const unsigned char *ciphertext = bytes + DIMS_SIGN_GCM_IV_BYTES;
    int ciphertext_length =
            length - DIMS_SIGN_GCM_IV_BYTES - DIMS_SIGN_GCM_TAG_BYTES;
    const unsigned char *tag = ciphertext + ciphertext_length;
    char *plaintext;
    int written = 0;
    int final = 0;

    /* The value holds an IV, at least one byte of ciphertext, and a tag. */
    if (ciphertext_length <= 0) {
        return DIMS_SIGN_BAD_EURL;
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        return DIMS_SIGN_CRYPTO;
    }

    plaintext = malloc((size_t) ciphertext_length + 1);
    if (plaintext == NULL) {
        EVP_CIPHER_CTX_free(context);
        return DIMS_SIGN_MEMORY;
    }

    if (EVP_DecryptInit_ex(context, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                    DIMS_SIGN_GCM_IV_BYTES, NULL) != 1 ||
            EVP_DecryptInit_ex(context, NULL, NULL, key, iv) != 1 ||
            EVP_DecryptUpdate(context, (unsigned char *) plaintext, &written,
                    ciphertext, ciphertext_length) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG,
                    DIMS_SIGN_GCM_TAG_BYTES, (void *) (uintptr_t) tag) != 1) {
        EVP_CIPHER_CTX_free(context);
        free(plaintext);
        return DIMS_SIGN_BAD_EURL;
    }

    /* The tag check happens here. A value someone edited fails. */
    if (EVP_DecryptFinal_ex(context, (unsigned char *) plaintext + written,
            &final) != 1) {
        EVP_CIPHER_CTX_free(context);
        free(plaintext);
        return DIMS_SIGN_BAD_EURL;
    }

    EVP_CIPHER_CTX_free(context);

    plaintext[written + final] = '\0';
    *out = plaintext;

    return DIMS_SIGN_OK;
}

static dims_sign_status
decrypt_ecb(const unsigned char *bytes, int length, const unsigned char *key,
            char **out)
{
    EVP_CIPHER_CTX *context;
    char *plaintext;
    int written = 0;
    int final = 0;

    /* One AES block is the shortest thing this can decrypt. */
    if (length < DIMS_SIGN_AES_BLOCK_BYTES) {
        return DIMS_SIGN_BAD_EURL;
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        return DIMS_SIGN_CRYPTO;
    }

    /* EVP_DecryptUpdate may write up to one block past the input length, and
     * the terminator needs a byte of its own. */
    plaintext = malloc((size_t) length + DIMS_SIGN_AES_BLOCK_BYTES + 1);
    if (plaintext == NULL) {
        EVP_CIPHER_CTX_free(context);
        return DIMS_SIGN_MEMORY;
    }

    if (EVP_DecryptInit_ex(context, EVP_aes_128_ecb(), NULL, key, NULL) != 1 ||
            EVP_DecryptUpdate(context, (unsigned char *) plaintext, &written,
                    bytes, length) != 1 ||
            EVP_DecryptFinal_ex(context, (unsigned char *) plaintext + written,
                    &final) != 1) {
        EVP_CIPHER_CTX_free(context);
        free(plaintext);
        return DIMS_SIGN_BAD_EURL;
    }

    EVP_CIPHER_CTX_free(context);

    plaintext[written + final] = '\0';
    *out = plaintext;

    return DIMS_SIGN_OK;
}

dims_sign_status
dims_sign_eurl_decrypt(const char *eurl,
                       const unsigned char key[DIMS_SIGN_KEY_BYTES],
                       dims_sign_cipher cipher, char **out)
{
    unsigned char *bytes = NULL;
    int length;
    dims_sign_status status;

    if (out == NULL || eurl == NULL || key == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    length = base64_decode(eurl, &bytes);
    if (length < 0) {
        return DIMS_SIGN_BAD_EURL;
    }

    if (cipher == DIMS_SIGN_EURL_ECB) {
        status = decrypt_ecb(bytes, length, key, out);
    } else {
        status = decrypt_gcm(bytes, length, key, out);
    }

    free(bytes);

    return status;
}
