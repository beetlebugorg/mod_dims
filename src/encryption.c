
#include <stddef.h>
#include <httpd.h>
#include <http_log.h>
#include <apr_base64.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

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

    int decrypted_length;
    int plaintext_length, out_length;
    char *plaintext = apr_palloc(r->pool, encrypted_length * sizeof(char));
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
    int encrypted_length = apr_base64_decode_len((const char *)base64_encrypted_text);
    unsigned char *encrypted_data = apr_palloc(r->pool, encrypted_length);
    int decoded_length = apr_base64_decode((char *)encrypted_data, (const char *)base64_encrypted_text);

    // Extract IV (12 bytes), ciphertext, and tag (16 bytes)
    unsigned char *iv = encrypted_data;
    unsigned char *encrypted_text = encrypted_data + 12; // 12-byte IV
    int ciphertext_length = decoded_length - 12 - 16; // 16-byte tag at the end
    unsigned char *tag = encrypted_text + ciphertext_length; // 16-byte tag

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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) {
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

    plaintext = apr_palloc(r->pool, ciphertext_length + 1); // +1 for null terminator
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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
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