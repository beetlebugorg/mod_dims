/*
 * Decrypting the eurl request parameter.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "encryption.h"

#include <openssl/evp.h>
#include <openssl/err.h>
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

    /*
     * One AES block is the shortest thing this can decrypt, and a negative
     * length reaches EVP_DecryptUpdate as a size_t near its maximum.
     */
    if (encrypted_text == NULL || encrypted_length < DIMS_AES_BLOCK_BYTES) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "eurl decodes to %d bytes, which is shorter than one AES block",
                encrypted_length);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    /*
     * The allocation was exactly encrypted_length, which is too small twice
     * over. EVP_DecryptUpdate is documented to write up to one block past the
     * input length, and the terminator below needs a byte of its own. The
     * old buffer had room for neither, so a plaintext that filled the block
     * put the terminator past the end.
     */
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
     *
     * Anything shorter made ciphertext_length negative. tag then pointed
     * before the buffer, apr_palloc received the negative length promoted to a
     * size near its maximum, and EVP_DecryptUpdate received it as a length.
     * The caller chooses this input and no signature is checked before it, so
     * every one of those runs on a value a stranger picked.
     *
     * Measured on this toolchain, two libraries happen to catch it: apr_palloc
     * returns NULL for the huge size, and EVP_DecryptUpdate returns an error
     * for a negative length. The module should not depend on either. Check the
     * length here, where the arithmetic is.
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
