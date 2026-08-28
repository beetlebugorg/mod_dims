/*
 * The /dims5/ signature.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "signature.h"

#include <apr_tables.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <string.h>
#include <strings.h>

/* The parameters a signature never covers. */
static const char *const dims_unsigned_params[] = {
    "sig", "url", "eurl", "_keys", "download", NULL
};

static int
is_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.' || c == '~';
}

char *
dims_query_escape(apr_pool_t *pool, const char *value)
{
    static const char hex[] = "0123456789ABCDEF";
    const unsigned char *in;
    char *out;
    char *at;

    if (value == NULL) {
        return apr_pstrdup(pool, "");
    }

    /* Three bytes per input byte at most, and a terminator. */
    out = apr_palloc(pool, strlen(value) * 3 + 1);
    at = out;

    for (in = (const unsigned char *) value; *in != '\0'; in++) {
        if (is_unreserved(*in)) {
            *at++ = (char) *in;
        } else if (*in == ' ') {
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

/* One name and one value, already decoded. */
typedef struct {
    const char *name;
    const char *value;
    int order;
} dims_param;

static int
by_name_then_order(const void *a, const void *b)
{
    const dims_param *left = a;
    const dims_param *right = b;
    int cmp = strcmp(left->name, right->name);

    /* A parameter with several values keeps the order the query gave. */
    return (cmp != 0) ? cmp : (left->order - right->order);
}

static int
is_unsigned_param(const char *name)
{
    int i;

    for (i = 0; dims_unsigned_params[i] != NULL; i++) {
        if (strcmp(name, dims_unsigned_params[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

/* Decodes one percent encoded query component in place. */
static void
query_unescape(char *value)
{
    char *read = value;
    char *write = value;

    while (*read != '\0') {
        if (*read == '+') {
            *write++ = ' ';
            read++;
        } else if (read[0] == '%' && apr_isxdigit(read[1]) &&
                   apr_isxdigit(read[2])) {
            char pair[3] = { read[1], read[2], '\0' };

            *write++ = (char) strtol(pair, NULL, 16);
            read += 3;
        } else {
            *write++ = *read++;
        }
    }

    *write = '\0';
}

char *
dims_signed_query(apr_pool_t *pool, const char *query)
{
    apr_array_header_t *params;
    char *copy;
    char *token;
    char *state = NULL;
    char *out;
    int i;

    params = apr_array_make(pool, 8, sizeof(dims_param));

    if (query == NULL || *query == '\0') {
        return apr_pstrdup(pool, "");
    }

    copy = apr_pstrdup(pool, query);

    for (token = apr_strtok(copy, "&", &state); token != NULL;
            token = apr_strtok(NULL, "&", &state)) {
        char *equals = strchr(token, '=');
        dims_param *param;
        char *name;
        char *value;

        if (*token == '\0') {
            continue;
        }

        if (equals != NULL) {
            *equals = '\0';
            value = apr_pstrdup(pool, equals + 1);
        } else {
            value = apr_pstrdup(pool, "");
        }

        name = apr_pstrdup(pool, token);
        query_unescape(name);
        query_unescape(value);

        if (is_unsigned_param(name)) {
            continue;
        }

        param = (dims_param *) apr_array_push(params);
        param->name = name;
        param->value = value;
        param->order = params->nelts;
    }

    qsort(params->elts, (size_t) params->nelts, sizeof(dims_param),
          by_name_then_order);

    out = apr_pstrdup(pool, "");
    for (i = 0; i < params->nelts; i++) {
        const dims_param *param = &((const dims_param *) params->elts)[i];

        out = apr_pstrcat(pool, out, (i > 0) ? "&" : "",
                          dims_query_escape(pool, param->name), "=",
                          dims_query_escape(pool, param->value), NULL);
    }

    return out;
}

char *
dims_signature_message(apr_pool_t *pool, const char *commands,
                       const char *image_url, const char *signed_query)
{
    return apr_pstrcat(pool,
            commands ? commands : "", "\n",
            image_url ? image_url : "", "\n",
            signed_query ? signed_query : "", NULL);
}

char *
dims_signature_compute(apr_pool_t *pool, const char *key, const char *message)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    char *out;
    unsigned int i;

    if (key == NULL || message == NULL) {
        return NULL;
    }

    if (HMAC(EVP_sha256(), key, (int) strlen(key),
             (const unsigned char *) message, strlen(message),
             digest, &length) == NULL) {
        return NULL;
    }

    out = apr_palloc(pool, (apr_size_t) length * 2 + 1);
    for (i = 0; i < length; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    out[length * 2] = '\0';

    return out;
}

int
dims_signature_equal(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    if (strlen(a) != DIMS_SIGNATURE_LENGTH ||
            strlen(b) != DIMS_SIGNATURE_LENGTH) {
        return 0;
    }

    return CRYPTO_memcmp(a, b, DIMS_SIGNATURE_LENGTH) == 0;
}

int
dims_signature_field_ok(const char *field)
{
    const unsigned char *at;

    if (field == NULL) {
        return 1;
    }

    for (at = (const unsigned char *) field; *at != '\0'; at++) {
        if (*at < 0x20 || *at == 0x7F) {
            return 0;
        }
    }

    return 1;
}
