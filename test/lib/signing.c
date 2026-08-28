/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "signing.h"
#include "request.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * mod_dims signs expires + secret + commands + image_url, then the value of
 * each parameter _keys names, in _keys order. See src/mod_dims.c:1376-1390.
 * The comparison uses the first six characters only.
 */
char *
dims_signature_dims4(const char *expires, const char *secret, const char *commands,
                     const char *image_url, const char *const *extra_values,
                     size_t extra_count)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    char *hex;
    unsigned int i;

    if (context == NULL) {
        return NULL;
    }

    if (EVP_DigestInit_ex(context, EVP_md5(), NULL) != 1) {
        EVP_MD_CTX_free(context);
        return NULL;
    }

    EVP_DigestUpdate(context, expires, strlen(expires));
    EVP_DigestUpdate(context, secret, strlen(secret));
    EVP_DigestUpdate(context, commands, strlen(commands));
    EVP_DigestUpdate(context, image_url, strlen(image_url));
    for (i = 0; i < extra_count; i++) {
        EVP_DigestUpdate(context, extra_values[i], strlen(extra_values[i]));
    }

    if (EVP_DigestFinal_ex(context, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(context);
        return NULL;
    }
    EVP_MD_CTX_free(context);

    hex = malloc((size_t) digest_len * 2 + 1);
    if (hex == NULL) {
        return NULL;
    }
    for (i = 0; i < digest_len; i++) {
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }

    return hex;
}

/* Splits "a=1&b=2" and appends the value of each key _keys names. */
static size_t
values_for_keys(const char *extra, const char *keys, char **values, size_t max)
{
    char *keys_copy;
    char *key;
    char *state = NULL;
    size_t count = 0;

    if (extra == NULL || keys == NULL) {
        return 0;
    }

    keys_copy = strdup(keys);
    if (keys_copy == NULL) {
        return 0;
    }

    for (key = strtok_r(keys_copy, ",", &state); key != NULL && count < max;
         key = strtok_r(NULL, ",", &state)) {
        const char *cursor = extra;
        size_t key_len = strlen(key);

        while (cursor != NULL && *cursor != '\0') {
            const char *end;

            if (strncmp(cursor, key, key_len) == 0 && cursor[key_len] == '=') {
                cursor += key_len + 1;
                end = strchr(cursor, '&');
                if (end == NULL) {
                    values[count] = strdup(cursor);
                } else {
                    values[count] = strndup(cursor, (size_t) (end - cursor));
                }
                count++;
                break;
            }

            cursor = strchr(cursor, '&');
            if (cursor != NULL) {
                cursor++;
            }
        }
    }

    free(keys_copy);
    return count;
}

/*
 * httpd decodes r->uri before the module reads it, and the signature covers
 * that decoded string. A percent sign in a command argument therefore has to
 * travel as %25. crop/50%x50% is the case that needs it.
 */
static char *
escape_percent(const char *commands)
{
    size_t len = strlen(commands);
    char *out = malloc(len * 3 + 1);
    size_t i, j = 0;

    if (out == NULL) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (commands[i] == '%') {
            out[j++] = '%';
            out[j++] = '2';
            out[j++] = '5';
        } else {
            out[j++] = commands[i];
        }
    }
    out[j] = '\0';

    return out;
}

char *
dims_sign_dims4_with(const char *signature, const char *expires, const char *commands,
                     const char *image_url, const char *extra, const char *keys)
{
    char *encoded_url = dims_urlencode(image_url);
    char *escaped_commands = escape_percent(commands);
    char *path;
    size_t len;

    if (encoded_url == NULL || escaped_commands == NULL) {
        free(encoded_url);
        free(escaped_commands);
        return NULL;
    }

    len = strlen(escaped_commands) + strlen(encoded_url) + strlen(signature) + strlen(expires) +
          (extra != NULL ? strlen(extra) : 0) + (keys != NULL ? strlen(keys) : 0) + 128;

    path = malloc(len);
    if (path == NULL) {
        free(encoded_url);
        return NULL;
    }

    snprintf(path, len, "/dims4/%s/%s/%s/%s/?url=%s%s%s%s%s",
             DIMS_TEST_CLIENT, signature, expires, escaped_commands, encoded_url,
             (extra != NULL) ? "&" : "", (extra != NULL) ? extra : "",
             (keys != NULL) ? "&_keys=" : "", (keys != NULL) ? keys : "");

    free(escaped_commands);
    free(encoded_url);
    return path;
}

char *
dims_sign_dims4(const char *commands, const char *image_url, const char *extra,
                const char *keys)
{
    char *values[16] = { NULL };
    char signed_commands[512];
    size_t count;
    char *signature;
    char *path;
    size_t i;

    count = values_for_keys(extra, keys, values, 16);

    /*
     * dims_handle_request consumes the client id, the signature, and the
     * expiry with ap_getword, then signs what is left of the path. The URL
     * ends with a slash, so the signed string ends with one too. See
     * src/mod_dims.c:1367-1381.
     */
    snprintf(signed_commands, sizeof(signed_commands), "%s/", commands);

    signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                     signed_commands, image_url,
                                     (const char *const *) values, count);

    for (i = 0; i < count; i++) {
        free(values[i]);
    }

    if (signature == NULL) {
        return NULL;
    }

    /* mod_dims compares six characters. Send the whole digest: a correct
     * client has no reason to truncate, and the service accepts either. */
    path = dims_sign_dims4_with(signature, DIMS_TEST_EXPIRES, commands, image_url,
                                extra, keys);
    free(signature);

    return path;
}
