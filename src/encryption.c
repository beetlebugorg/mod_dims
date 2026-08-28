/*
 * Decrypting the eurl request parameter.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "encryption.h"

#include <apr_escape.h>
#include <apr_lib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <string.h>

int
aes_errors(const char *message, size_t length, void *u)
{
    request_rec *r = (request_rec *) u;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s", message);
    return 0;
}

char *
aes_128_decrypt(request_rec *r, unsigned char *key, unsigned char *encrypted_text, int encrypted_length)
{
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_cb(aes_errors, r);
        return NULL;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        ERR_print_errors_cb(aes_errors, r);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int plaintext_length, out_length;
    char *plaintext;

    /* One AES block is the shortest thing this can decrypt. */
    if (encrypted_text == NULL || encrypted_length < DIMS_AES_BLOCK_BYTES) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "eurl decodes to %d bytes, which is shorter than one AES block",
                encrypted_length);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    /* EVP_DecryptUpdate may write up to one block past the input length, and
     * the terminator below needs a byte of its own. */
    plaintext = apr_palloc(r->pool,
            (apr_size_t) encrypted_length + DIMS_AES_BLOCK_BYTES + 1);
    if (EVP_DecryptUpdate(ctx, (unsigned char *) plaintext, &out_length, encrypted_text, encrypted_length)) {
        plaintext_length = out_length;

        if (!EVP_DecryptFinal_ex(ctx, (unsigned char *) plaintext + out_length, &plaintext_length)) {
            ERR_print_errors_cb(aes_errors, r);
            EVP_CIPHER_CTX_free(ctx);
            return NULL;
        }

        plaintext_length += out_length;
        plaintext[plaintext_length] = '\0';
    } else {
        ERR_print_errors_cb(aes_errors, r);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

char *
aes_128_gcm_decrypt(request_rec *r, unsigned char *key, unsigned char *base64_encrypted_text) {
    EVP_CIPHER_CTX *ctx;
    int ret;
    int plaintext_length = 0;
    int out_length;
    char *plaintext;

    // Decode the Base64 input
    int encrypted_length;
    unsigned char *encrypted_data;
    int decoded_length;
    unsigned char *iv;
    unsigned char *encrypted_text;
    int ciphertext_length;
    unsigned char *tag;

    if (base64_encrypted_text == NULL) {
        return NULL;
    }

    encrypted_length = apr_base64_decode_len((const char *) base64_encrypted_text);
    if (encrypted_length <= 0) {
        return NULL;
    }

    encrypted_data = apr_palloc(r->pool, (apr_size_t) encrypted_length);
    decoded_length = apr_base64_decode((char *) encrypted_data,
            (const char *) base64_encrypted_text);

    /*
     * The value has to hold an IV, at least one byte of ciphertext, and a tag.
     * Anything shorter makes ciphertext_length negative, and it reaches a
     * pointer offset, an allocation size, and a decryption length.
     *
     * decoded_length is compared with what the decoder was told to expect,
     * because the caller chooses the input and the two can disagree.
     */
    if (decoded_length <= DIMS_GCM_IV_BYTES + DIMS_GCM_TAG_BYTES ||
            decoded_length > encrypted_length) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "eurl decodes to %d bytes, which cannot hold an IV, a "
                "ciphertext, and a tag", decoded_length);
        return NULL;
    }

    // Extract IV (12 bytes), ciphertext, and tag (16 bytes)
    iv = encrypted_data;
    encrypted_text = encrypted_data + DIMS_GCM_IV_BYTES;
    ciphertext_length = decoded_length - DIMS_GCM_IV_BYTES - DIMS_GCM_TAG_BYTES;
    tag = encrypted_text + ciphertext_length;

    // Initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Failed to create new EVP_CIPHER_CTX");
        ERR_print_errors_cb(aes_errors, r);
        return NULL;
    }

    // Initialize the decryption operation
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "EVP_DecryptInit_ex failed (1)");
        ERR_print_errors_cb(aes_errors, r);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Set the IV length, if necessary
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, DIMS_GCM_IV_BYTES, NULL)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "EVP_CIPHER_CTX_ctrl failed to set IV length");
        ERR_print_errors_cb(aes_errors, r);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Set the key and IV
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "EVP_DecryptInit_ex failed (2)");
        ERR_print_errors_cb(aes_errors, r);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    plaintext = apr_palloc(r->pool, (apr_size_t) ciphertext_length + 1);
    if (!plaintext) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Memory allocation failed");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Provide the message to be decrypted and obtain the plaintext output
    if (!EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &out_length, encrypted_text, ciphertext_length)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "EVP_DecryptUpdate failed");
        ERR_print_errors_cb(aes_errors, r);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    plaintext_length = out_length;

    // Set expected tag value (must be done after EVP_DecryptUpdate)
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, DIMS_GCM_TAG_BYTES, tag)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "EVP_CIPHER_CTX_ctrl failed to set tag");
        ERR_print_errors_cb(aes_errors, r);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Finalize the decryption
    ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + plaintext_length, &out_length);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_length += out_length;
        plaintext[plaintext_length] = '\0';  // Explicitly add the null terminator
        return plaintext;
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "EVP_DecryptFinal_ex failed");
        ERR_print_errors_cb(aes_errors, r);
        return NULL;
    }
}

/* The salt the key derivation uses. Changing it invalidates every eurl. */
static const unsigned char dims_kdf_salt[] = "go-dims";

int
dims_derive_key(const char *secret, unsigned char *key)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *ctx;
    OSSL_PARAM params[5];
    OSSL_PARAM *at = params;
    int ok;

    if (secret == NULL || key == NULL) {
        return 0;
    }

    if (strncmp(secret, "sha1:", 5) == 0) {
        unsigned char digest[SHA_DIGEST_LENGTH];
        char hex[SHA_DIGEST_LENGTH * 2 + 1];
        int i;

        secret += 5;
        SHA1((const unsigned char *) secret, strlen(secret), digest);

        if (apr_escape_hex(hex, digest, SHA_DIGEST_LENGTH, 0, NULL) != APR_SUCCESS) {
            return 0;
        }

        for (i = 0; i < DIMS_AES_KEY_BYTES; i++) {
            key[i] = (unsigned char) apr_toupper(hex[i]);
        }

        return 1;
    }

    if (strncmp(secret, "hkdf:", 5) == 0) {
        secret += 5;
    }

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        return 0;
    }

    ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == NULL) {
        return 0;
    }

    *at++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char *) "SHA256", 0);
    *at++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            (void *) secret, strlen(secret));
    *at++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
            (void *) dims_kdf_salt, sizeof(dims_kdf_salt) - 1);
    *at++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *) "", 0);
    *at = OSSL_PARAM_construct_end();

    ok = EVP_KDF_derive(ctx, key, DIMS_AES_KEY_BYTES, params) > 0;
    EVP_KDF_CTX_free(ctx);

    return ok;
}
