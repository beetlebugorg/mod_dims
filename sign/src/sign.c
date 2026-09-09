/*
 * The mod_dims signing rules.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "dims_sign.h"
#include "dims_sign_internal.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>

/* The parameters a /dims5/ signature never covers. */
static const char *const unsigned_params[] = {
    "sig", "url", "eurl", "_keys", "download", NULL
};

/* -- A growable string ------------------------------------------------- */

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
    int failed;
} buffer;

static void
buffer_init(buffer *b)
{
    b->data = NULL;
    b->length = 0;
    b->capacity = 0;
    b->failed = 0;
}

static void
buffer_reserve(buffer *b, size_t extra)
{
    size_t needed;
    size_t capacity;
    char *grown;

    if (b->failed) {
        return;
    }

    if (extra > (size_t) -1 - b->length - 1) {
        b->failed = 1;
        return;
    }

    needed = b->length + extra + 1;
    if (needed <= b->capacity) {
        return;
    }

    capacity = (b->capacity != 0) ? b->capacity : 64;
    while (capacity < needed) {
        if (capacity > (size_t) -1 / 2) {
            b->failed = 1;
            return;
        }
        capacity *= 2;
    }

    grown = realloc(b->data, capacity);
    if (grown == NULL) {
        b->failed = 1;
        return;
    }

    b->data = grown;
    b->capacity = capacity;
}

static void
buffer_add_bytes(buffer *b, const char *at, size_t length)
{
    buffer_reserve(b, length);
    if (b->failed) {
        return;
    }

    memcpy(b->data + b->length, at, length);
    b->length += length;
    b->data[b->length] = '\0';
}

static void
buffer_add(buffer *b, const char *text)
{
    if (text != NULL) {
        buffer_add_bytes(b, text, strlen(text));
    }
}

static void
buffer_add_char(buffer *b, char c)
{
    buffer_add_bytes(b, &c, 1);
}

/* Hands the string to the caller, or NULL when an allocation failed. */
static char *
buffer_take(buffer *b)
{
    char *data;

    if (b->failed) {
        free(b->data);
        buffer_init(b);
        return NULL;
    }

    if (b->data == NULL) {
        buffer_reserve(b, 0);
        if (b->failed) {
            return NULL;
        }
        b->data[0] = '\0';
    }

    data = b->data;
    buffer_init(b);

    return data;
}

static void
buffer_release(buffer *b)
{
    free(b->data);
    buffer_init(b);
}

/* -- Percent encoding and decoding -------------------------------------- */

static int
is_unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.' || c == '~';
}

static int
hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

static void
buffer_add_escaped(buffer *b, const char *value)
{
    static const char hex[] = "0123456789ABCDEF";
    const unsigned char *at;

    if (value == NULL) {
        return;
    }

    for (at = (const unsigned char *) value; *at != '\0'; at++) {
        if (is_unreserved(*at)) {
            buffer_add_char(b, (char) *at);
        } else if (*at == ' ') {
            buffer_add_char(b, '+');
        } else {
            buffer_add_char(b, '%');
            buffer_add_char(b, hex[*at >> 4]);
            buffer_add_char(b, hex[*at & 0x0F]);
        }
    }
}

dims_sign_status
dims_sign_escape(const char *value, char **out)
{
    buffer escaped;

    if (out == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    buffer_init(&escaped);
    buffer_add_escaped(&escaped, value);

    *out = buffer_take(&escaped);

    return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
}

/*
 * Decodes one query component the way the module does. A plus is a space, and
 * a percent escape that is not two hex digits passes through as it is. The
 * module leaves such an escape alone, so the two agree on every input.
 */
static char *
decode_component(const char *at, size_t length)
{
    buffer decoded;
    size_t i;

    buffer_init(&decoded);

    for (i = 0; i < length; i++) {
        if (at[i] == '+') {
            buffer_add_char(&decoded, ' ');
        } else if (at[i] == '%' && i + 2 < length &&
                   hex_value((unsigned char) at[i + 1]) >= 0 &&
                   hex_value((unsigned char) at[i + 2]) >= 0) {
            int value = hex_value((unsigned char) at[i + 1]) * 16 +
                        hex_value((unsigned char) at[i + 2]);

            buffer_add_char(&decoded, (char) value);
            i += 2;
        } else {
            buffer_add_char(&decoded, at[i]);
        }
    }

    return buffer_take(&decoded);
}

/*
 * Decodes a path or an image URL. A plus stays a plus, because the module
 * decodes both with ap_unescape_url, which does not read a plus as a space.
 *
 * A percent escape that is not two hex digits is an error, and so is %00: a C
 * string cannot hold the byte it decodes to.
 */
static dims_sign_status
decode_strict(const char *at, size_t length, char **out)
{
    buffer decoded;
    size_t i;

    buffer_init(&decoded);

    for (i = 0; i < length; i++) {
        if (at[i] == '%') {
            int high;
            int low;

            if (i + 2 >= length) {
                buffer_release(&decoded);
                return DIMS_SIGN_BAD_URL;
            }

            high = hex_value((unsigned char) at[i + 1]);
            low = hex_value((unsigned char) at[i + 2]);
            if (high < 0 || low < 0 || (high == 0 && low == 0)) {
                buffer_release(&decoded);
                return DIMS_SIGN_BAD_URL;
            }

            buffer_add_char(&decoded, (char) (high * 16 + low));
            i += 2;
        } else {
            buffer_add_char(&decoded, at[i]);
        }
    }

    *out = buffer_take(&decoded);

    return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
}

/* -- The canonical query ------------------------------------------------ */

typedef struct {
    char *name;
    char *value;
    size_t order;
} param;

static int
by_name_then_order(const void *a, const void *b)
{
    const param *left = a;
    const param *right = b;
    int cmp = strcmp(left->name, right->name);

    /* A name that appears more than once keeps the order the query gave. */
    if (cmp != 0) {
        return cmp;
    }

    return (left->order < right->order) ? -1 : (left->order > right->order);
}

static int
is_unsigned_param(const char *name)
{
    size_t i;

    for (i = 0; unsigned_params[i] != NULL; i++) {
        if (strcmp(name, unsigned_params[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

/* An upper bound on the token count: one more than the ampersand count. */
static size_t
token_limit(const char *query)
{
    size_t count = 1;
    const char *at;

    for (at = query; *at != '\0'; at++) {
        if (*at == '&') {
            count++;
        }
    }

    return count;
}

static void
release_params(param *list, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        free(list[i].name);
        free(list[i].value);
    }

    free(list);
}

dims_sign_status
dims_sign_canonical_query(const char *query, char **out)
{
    param *list;
    size_t count = 0;
    size_t i;
    const char *at;
    buffer canonical;

    if (out == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    if (query == NULL || *query == '\0') {
        *out = calloc(1, 1);
        return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
    }

    list = calloc(token_limit(query), sizeof(*list));
    if (list == NULL) {
        return DIMS_SIGN_MEMORY;
    }

    at = query;
    while (*at != '\0') {
        const char *end = strchr(at, '&');
        const char *equals;
        size_t length;

        if (end == NULL) {
            end = at + strlen(at);
        }

        length = (size_t) (end - at);
        equals = memchr(at, '=', length);

        if (length > 0) {
            param *entry = &list[count];

            if (equals != NULL) {
                entry->name = decode_component(at, (size_t) (equals - at));
                entry->value = decode_component(equals + 1,
                        (size_t) (end - equals - 1));
            } else {
                /* A parameter with no equals sign has an empty value. */
                entry->name = decode_component(at, length);
                entry->value = calloc(1, 1);
            }

            if (entry->name == NULL || entry->value == NULL) {
                free(entry->name);
                free(entry->value);
                release_params(list, count);
                return DIMS_SIGN_MEMORY;
            }

            if (is_unsigned_param(entry->name)) {
                free(entry->name);
                free(entry->value);
                entry->name = NULL;
                entry->value = NULL;
            } else {
                entry->order = count;
                count++;
            }
        }

        at = (*end == '\0') ? end : end + 1;
    }

    qsort(list, count, sizeof(*list), by_name_then_order);

    buffer_init(&canonical);
    for (i = 0; i < count; i++) {
        if (i > 0) {
            buffer_add_char(&canonical, '&');
        }
        buffer_add_escaped(&canonical, list[i].name);
        buffer_add_char(&canonical, '=');
        buffer_add_escaped(&canonical, list[i].value);
    }

    release_params(list, count);

    *out = buffer_take(&canonical);

    return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
}

/* -- The digests -------------------------------------------------------- */

static void
to_hex(const unsigned char *bytes, unsigned int count, char *out)
{
    static const char hex[] = "0123456789abcdef";
    unsigned int i;

    for (i = 0; i < count; i++) {
        out[i * 2] = hex[bytes[i] >> 4];
        out[i * 2 + 1] = hex[bytes[i] & 0x0F];
    }

    out[count * 2] = '\0';
}

dims_sign_status
dims_sign_dims5_digest(const char *key, const char *commands,
                       const char *image_url, const char *canonical_query,
                       char out[DIMS_SIGN_DIMS5_LENGTH + 1])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    buffer message;
    char *text;

    if (out == NULL || key == NULL || *key == '\0') {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    if (!dims_sign_field_ok(commands) || !dims_sign_field_ok(image_url)) {
        return DIMS_SIGN_BAD_FIELD;
    }

    buffer_init(&message);
    buffer_add(&message, commands);
    buffer_add_char(&message, '\n');
    buffer_add(&message, image_url);
    buffer_add_char(&message, '\n');
    buffer_add(&message, canonical_query);

    text = buffer_take(&message);
    if (text == NULL) {
        return DIMS_SIGN_MEMORY;
    }

    if (HMAC(EVP_sha256(), key, (int) strlen(key),
             (const unsigned char *) text, strlen(text),
             digest, &length) == NULL ||
            length * 2 != DIMS_SIGN_DIMS5_LENGTH) {
        free(text);
        return DIMS_SIGN_CRYPTO;
    }

    free(text);
    to_hex(digest, length, out);

    return DIMS_SIGN_OK;
}

/* The expiry, the secret, the commands, the image URL, and the keyed values. */
static char *
dims4_message(const char *secret, const char *expires, const char *commands,
              const char *image_url, const dims_sign_param *keys,
              size_t key_count)
{
    buffer message;
    size_t i;

    buffer_init(&message);
    buffer_add(&message, expires);
    buffer_add(&message, secret);
    buffer_add(&message, commands);
    buffer_add(&message, image_url);

    for (i = 0; i < key_count; i++) {
        /* A NULL value contributes nothing. */
        buffer_add(&message, keys[i].value);
    }

    return buffer_take(&message);
}

dims_sign_status
dims_sign_dims4_digest(const char *secret, const char *expires,
                       const char *commands, const char *image_url,
                       const dims_sign_param *keys, size_t key_count,
                       char out[DIMS_SIGN_DIMS4_DIGEST + 1])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    char *text;

    if (out == NULL || secret == NULL || *secret == '\0' || expires == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    text = dims4_message(secret, expires, commands, image_url, keys, key_count);
    if (text == NULL) {
        return DIMS_SIGN_MEMORY;
    }

    if (!EVP_Digest(text, strlen(text), digest, &length, EVP_md5(), NULL) ||
            length * 2 != DIMS_SIGN_DIMS4_DIGEST) {
        free(text);
        return DIMS_SIGN_CRYPTO;
    }

    free(text);
    to_hex(digest, length, out);

    return DIMS_SIGN_OK;
}

/* -- The comparisons ---------------------------------------------------- */

int
dims_sign_dims5_equal(const char *expected, const char *given)
{
    if (expected == NULL || given == NULL) {
        return 0;
    }

    if (strlen(expected) != DIMS_SIGN_DIMS5_LENGTH ||
            strlen(given) != DIMS_SIGN_DIMS5_LENGTH) {
        return 0;
    }

    return CRYPTO_memcmp(expected, given, DIMS_SIGN_DIMS5_LENGTH) == 0;
}

static unsigned char
fold(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (unsigned char) (c - 'A' + 'a') : c;
}

int
dims_sign_dims4_equal(const char *expected, const char *given)
{
    unsigned char difference = 0;
    size_t i;

    if (expected == NULL || given == NULL) {
        return 0;
    }

    if (strlen(expected) < DIMS_SIGN_DIMS4_LENGTH ||
            strlen(given) < DIMS_SIGN_DIMS4_LENGTH) {
        return 0;
    }

    /* Every byte is read whatever the answer. */
    for (i = 0; i < DIMS_SIGN_DIMS4_LENGTH; i++) {
        difference |= (unsigned char) (fold((unsigned char) expected[i]) ^
                                       fold((unsigned char) given[i]));
    }

    return difference == 0;
}

int
dims_sign_field_ok(const char *field)
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

/* -- Reading a URL ------------------------------------------------------ */

typedef struct {
    const char *path;
    size_t path_length;
    const char *query;  /* After the question mark, or NULL. */
} url_parts;

static int
is_scheme_byte(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
}

/* Where the path starts. An absolute URL has an authority before it. */
static const char *
path_of(const char *url)
{
    const char *at = url;

    if ((*at >= 'A' && *at <= 'Z') || (*at >= 'a' && *at <= 'z')) {
        while (is_scheme_byte((unsigned char) *at)) {
            at++;
        }

        if (at[0] == ':' && at[1] == '/' && at[2] == '/') {
            at += 3;
            while (*at != '\0' && *at != '/' && *at != '?') {
                at++;
            }

            return at;
        }
    }

    return url;
}

static void
split_url(const char *url, url_parts *parts)
{
    const char *question;

    parts->path = path_of(url);
    question = strchr(parts->path, '?');

    if (question != NULL) {
        parts->path_length = (size_t) (question - parts->path);
        parts->query = question + 1;
    } else {
        parts->path_length = strlen(parts->path);
        parts->query = NULL;
    }
}

/* What follows the prefix in the path. */
static dims_sign_status
after_prefix(const url_parts *parts, const char *prefix, const char **rest,
             size_t *rest_length)
{
    size_t length = strlen(prefix);

    if (parts->path_length < length ||
            memcmp(parts->path, prefix, length) != 0) {
        return DIMS_SIGN_BAD_URL;
    }

    *rest = parts->path + length;
    *rest_length = parts->path_length - length;

    return DIMS_SIGN_OK;
}

/*
 * The last raw value of one query parameter, undecoded, or NULL.
 *
 * The name is compared as it appears in the query. The module reads the query
 * the same way, so a percent escape in a name does not match here either.
 */
static const char *
raw_value(const char *query, const char *name, size_t *length)
{
    size_t name_length = strlen(name);
    const char *found = NULL;
    const char *at;

    if (query == NULL) {
        return NULL;
    }

    at = query;
    while (*at != '\0') {
        const char *end = strchr(at, '&');
        size_t token_length;

        if (end == NULL) {
            end = at + strlen(at);
        }

        token_length = (size_t) (end - at);
        if (token_length > name_length && at[name_length] == '=' &&
                memcmp(at, name, name_length) == 0) {
            found = at + name_length + 1;
            *length = token_length - name_length - 1;
        }

        at = (*end == '\0') ? end : end + 1;
    }

    return found;
}

/* The image URL, decoded. The query must hold a url parameter. */
static dims_sign_status
read_image_url(const char *query, char **out)
{
    size_t length = 0;
    const char *value = raw_value(query, "url", &length);

    if (value == NULL) {
        return DIMS_SIGN_BAD_URL;
    }

    return decode_strict(value, length, out);
}

/* -- /dims5/ ------------------------------------------------------------ */

static dims_sign_status
dims5_fields(const char *url, const char *prefix, url_parts *parts,
             char **commands, char **image_url, char **canonical)
{
    dims_sign_status status;
    const char *rest;
    size_t rest_length;

    *commands = NULL;
    *image_url = NULL;
    *canonical = NULL;

    if (url == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    if (prefix == NULL || *prefix == '\0') {
        prefix = DIMS_SIGN_DIMS5_PREFIX;
    }

    split_url(url, parts);

    status = after_prefix(parts, prefix, &rest, &rest_length);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    status = decode_strict(rest, rest_length, commands);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    status = read_image_url(parts->query, image_url);
    if (status != DIMS_SIGN_OK) {
        free(*commands);
        *commands = NULL;
        return status;
    }

    status = dims_sign_canonical_query(parts->query, canonical);
    if (status != DIMS_SIGN_OK) {
        free(*commands);
        free(*image_url);
        *commands = NULL;
        *image_url = NULL;
        return status;
    }

    return DIMS_SIGN_OK;
}

/* Copies the query with every sig parameter left out. */
static void
buffer_add_query_without_sig(buffer *b, const char *query)
{
    const char *at = query;
    int written = 0;

    while (*at != '\0') {
        const char *end = strchr(at, '&');
        size_t length;
        const char *equals;
        size_t name_length;

        if (end == NULL) {
            end = at + strlen(at);
        }

        length = (size_t) (end - at);
        equals = memchr(at, '=', length);
        name_length = (equals != NULL) ? (size_t) (equals - at) : length;

        if (length > 0 &&
                !(name_length == 3 && memcmp(at, "sig", 3) == 0)) {
            if (written) {
                buffer_add_char(b, '&');
            }
            buffer_add_bytes(b, at, length);
            written = 1;
        }

        at = (*end == '\0') ? end : end + 1;
    }

    if (written) {
        buffer_add_char(b, '&');
    }
}

dims_sign_status
dims_sign_dims5_url(const char *url, const char *key, const char *prefix,
                    char **out)
{
    dims_sign_status status;
    char digest[DIMS_SIGN_DIMS5_LENGTH + 1];
    char *commands;
    char *image_url;
    char *canonical;
    url_parts parts;
    buffer signed_url;

    if (out == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    if (key == NULL || *key == '\0') {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    status = dims5_fields(url, prefix, &parts, &commands, &image_url,
                          &canonical);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    status = dims_sign_dims5_digest(key, commands, image_url, canonical,
                                    digest);
    free(commands);
    free(image_url);
    free(canonical);

    if (status != DIMS_SIGN_OK) {
        return status;
    }

    buffer_init(&signed_url);
    buffer_add_bytes(&signed_url, url,
                     (size_t) (parts.path - url) + parts.path_length);
    buffer_add_char(&signed_url, '?');
    buffer_add_query_without_sig(&signed_url, parts.query);
    buffer_add(&signed_url, "sig=");
    buffer_add(&signed_url, digest);

    *out = buffer_take(&signed_url);

    return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
}

dims_sign_status
dims_sign_dims5_message(const char *url, const char *prefix, char **out)
{
    dims_sign_status status;
    char *commands;
    char *image_url;
    char *canonical;
    url_parts parts;
    buffer message;

    if (out == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    status = dims5_fields(url, prefix, &parts, &commands, &image_url,
                          &canonical);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    buffer_init(&message);
    buffer_add(&message, commands);
    buffer_add_char(&message, '\n');
    buffer_add(&message, image_url);
    buffer_add_char(&message, '\n');
    buffer_add(&message, canonical);

    free(commands);
    free(image_url);
    free(canonical);

    *out = buffer_take(&message);

    return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
}

/* -- /dims4/ ------------------------------------------------------------ */

/* The four segments after the prefix. */
typedef struct {
    const char *client;
    size_t client_length;
    const char *signature;
    size_t signature_length;
    const char *expires;
    size_t expires_length;
    const char *commands;
    size_t commands_length;
} dims4_path;

static dims_sign_status
split_dims4_path(const char *rest, size_t rest_length, dims4_path *out)
{
    const char *end = rest + rest_length;
    const char *first = memchr(rest, '/', rest_length);
    const char *second;
    const char *third;
    size_t i;

    if (first == NULL) {
        return DIMS_SIGN_BAD_URL;
    }

    second = memchr(first + 1, '/', (size_t) (end - first - 1));
    if (second == NULL) {
        return DIMS_SIGN_BAD_URL;
    }

    third = memchr(second + 1, '/', (size_t) (end - second - 1));
    if (third == NULL) {
        return DIMS_SIGN_BAD_URL;
    }

    out->client = rest;
    out->client_length = (size_t) (first - rest);
    out->signature = first + 1;
    out->signature_length = (size_t) (second - first - 1);
    out->expires = second + 1;
    out->expires_length = (size_t) (third - second - 1);
    out->commands = third + 1;
    out->commands_length = (size_t) (end - third - 1);

    /* The module reads the expiry with atol, so any other text expires it. */
    if (out->expires_length == 0) {
        return DIMS_SIGN_BAD_URL;
    }
    for (i = 0; i < out->expires_length; i++) {
        if (out->expires[i] < '0' || out->expires[i] > '9') {
            return DIMS_SIGN_BAD_URL;
        }
    }

    /* The placeholder sets the length of the signature. */
    if (out->signature_length < DIMS_SIGN_DIMS4_LENGTH ||
            out->signature_length > DIMS_SIGN_DIMS4_DIGEST) {
        return DIMS_SIGN_BAD_URL;
    }

    return DIMS_SIGN_OK;
}

static void
release_keys(dims_sign_param *list, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        free((char *) list[i].name);
        free((char *) list[i].value);
    }

    free(list);
}

/* A NUL terminated copy of one byte range. */
static char *
copy_range(const char *at, size_t length)
{
    char *copy = malloc(length + 1);

    if (copy != NULL) {
        memcpy(copy, at, length);
        copy[length] = '\0';
    }

    return copy;
}

/*
 * The values _keys names, in _keys order, as they appear in the query.
 *
 * A name the query leaves out has a NULL value, which the digest skips.
 */
static dims_sign_status
read_keys(const char *query, dims_sign_param **out, size_t *count)
{
    size_t keys_length = 0;
    const char *keys = raw_value(query, "_keys", &keys_length);
    dims_sign_param *list;
    size_t found = 0;
    size_t at = 0;

    *out = NULL;
    *count = 0;

    if (keys == NULL || keys_length == 0) {
        return DIMS_SIGN_OK;
    }

    /* One name per byte at most, which every comma reduces. */
    list = calloc(keys_length, sizeof(*list));
    if (list == NULL) {
        return DIMS_SIGN_MEMORY;
    }

    while (at < keys_length) {
        size_t start = at;
        size_t length;
        const char *value;
        size_t value_length = 0;

        while (at < keys_length && keys[at] != ',') {
            at++;
        }

        length = at - start;
        at++;

        if (length == 0) {
            continue;
        }

        list[found].name = copy_range(keys + start, length);
        if (list[found].name == NULL) {
            release_keys(list, found);
            return DIMS_SIGN_MEMORY;
        }

        value = raw_value(query, list[found].name, &value_length);
        if (value != NULL) {
            list[found].value = copy_range(value, value_length);
            if (list[found].value == NULL) {
                release_keys(list, found + 1);
                return DIMS_SIGN_MEMORY;
            }
        }

        found++;
    }

    *out = list;
    *count = found;

    return DIMS_SIGN_OK;
}

/* Everything a /dims4/ signature covers, read out of one URL. */
typedef struct {
    url_parts parts;
    dims4_path path;
    char *commands;
    char *image_url;
    char *expires;
    dims_sign_param *keys;
    size_t key_count;
} dims4_fields;

static void
release_dims4_fields(dims4_fields *fields)
{
    free(fields->commands);
    free(fields->image_url);
    free(fields->expires);
    release_keys(fields->keys, fields->key_count);
}

static dims_sign_status
read_dims4_fields(const char *url, const char *prefix, dims4_fields *fields)
{
    dims_sign_status status;
    const char *rest;
    size_t rest_length;
    char *at;

    memset(fields, 0, sizeof(*fields));

    if (url == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    if (prefix == NULL || *prefix == '\0') {
        prefix = DIMS_SIGN_DIMS4_PREFIX;
    }

    split_url(url, &fields->parts);

    status = after_prefix(&fields->parts, prefix, &rest, &rest_length);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    status = split_dims4_path(rest, rest_length, &fields->path);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    status = decode_strict(fields->path.commands, fields->path.commands_length,
                           &fields->commands);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    /* A space travels as %20 and signs as a plus. */
    for (at = fields->commands; *at != '\0'; at++) {
        if (*at == ' ') {
            *at = '+';
        }
    }

    status = read_image_url(fields->parts.query, &fields->image_url);
    if (status != DIMS_SIGN_OK) {
        release_dims4_fields(fields);
        return status;
    }

    /* The module writes every plus in a /dims4/ image URL as a space after it
     * decodes the value. /dims5/ keeps the plus. */
    for (at = fields->image_url; *at != '\0'; at++) {
        if (*at == '+') {
            *at = ' ';
        }
    }

    status = read_keys(fields->parts.query, &fields->keys, &fields->key_count);
    if (status != DIMS_SIGN_OK) {
        release_dims4_fields(fields);
        return status;
    }

    fields->expires = copy_range(fields->path.expires,
                                 fields->path.expires_length);
    if (fields->expires == NULL) {
        release_dims4_fields(fields);
        return DIMS_SIGN_MEMORY;
    }

    return DIMS_SIGN_OK;
}

dims_sign_status
dims_sign_dims4_url(const char *url, const char *key, const char *prefix,
                    char **out)
{
    dims_sign_status status;
    char digest[DIMS_SIGN_DIMS4_DIGEST + 1];
    dims4_fields fields;
    buffer signed_url;

    if (out == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    if (key == NULL || *key == '\0') {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    status = read_dims4_fields(url, prefix, &fields);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    status = dims_sign_dims4_digest(key, fields.expires, fields.commands,
                                    fields.image_url, fields.keys,
                                    fields.key_count, digest);

    if (status != DIMS_SIGN_OK) {
        release_dims4_fields(&fields);
        return status;
    }

    /* The path is rebuilt from its four segments, so a placeholder equal to
     * the client id or to the expiry still works. */
    buffer_init(&signed_url);
    buffer_add_bytes(&signed_url, url, (size_t) (fields.path.client - url));
    buffer_add_bytes(&signed_url, fields.path.client,
                     fields.path.client_length);
    buffer_add_char(&signed_url, '/');
    buffer_add_bytes(&signed_url, digest, fields.path.signature_length);
    buffer_add_char(&signed_url, '/');
    buffer_add_bytes(&signed_url, fields.path.expires,
                     fields.path.expires_length);
    buffer_add_char(&signed_url, '/');
    buffer_add_bytes(&signed_url, fields.path.commands,
                     fields.path.commands_length);

    if (fields.parts.query != NULL) {
        buffer_add_char(&signed_url, '?');
        buffer_add(&signed_url, fields.parts.query);
    }

    release_dims4_fields(&fields);

    *out = buffer_take(&signed_url);

    return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
}

dims_sign_status
dims_sign_dims4_message(const char *url, const char *secret, const char *prefix,
                        char **out)
{
    dims_sign_status status;
    dims4_fields fields;

    if (out == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    if (secret == NULL || *secret == '\0') {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    status = read_dims4_fields(url, prefix, &fields);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    *out = dims4_message(secret, fields.expires, fields.commands,
                         fields.image_url, fields.keys, fields.key_count);

    release_dims4_fields(&fields);

    return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
}

/* -- eurl in place of url ------------------------------------------------ */

/*
 * Copies a signed URL with every url parameter replaced by one eurl.
 *
 * The eurl goes where the last url was, so the output holds the parameters in
 * the order the input gave. Neither name is in the canonical query, so the
 * signature still matches.
 *
 * escaped writes the value percent encoded, which /dims5/ needs and /dims4/
 * does not.
 */
static dims_sign_status
swap_url_for_eurl(const char *signed_url, const char *eurl, int escaped,
                  char **out)
{
    url_parts parts;
    buffer rebuilt;
    const char *at;
    size_t last = 0;
    size_t index = 0;
    int written = 0;
    char *value = NULL;

    split_url(signed_url, &parts);
    if (parts.query == NULL) {
        return DIMS_SIGN_BAD_URL;
    }

    /* Which token holds the last url. */
    for (at = parts.query; *at != '\0'; index++) {
        const char *end = strchr(at, '&');
        size_t length;

        if (end == NULL) {
            end = at + strlen(at);
        }

        length = (size_t) (end - at);
        if (length > 4 && memcmp(at, "url=", 4) == 0) {
            last = index;
        }

        at = (*end == '\0') ? end : end + 1;
    }

    if (escaped) {
        dims_sign_status status = dims_sign_escape(eurl, &value);

        if (status != DIMS_SIGN_OK) {
            return status;
        }
    }

    buffer_init(&rebuilt);
    buffer_add_bytes(&rebuilt, signed_url,
                     (size_t) (parts.path - signed_url) + parts.path_length);
    buffer_add_char(&rebuilt, '?');

    index = 0;
    for (at = parts.query; *at != '\0'; index++) {
        const char *end = strchr(at, '&');
        size_t length;
        int is_url;

        if (end == NULL) {
            end = at + strlen(at);
        }

        length = (size_t) (end - at);
        is_url = (length > 4 && memcmp(at, "url=", 4) == 0);

        if (length > 0 && (!is_url || index == last)) {
            if (written) {
                buffer_add_char(&rebuilt, '&');
            }

            if (is_url) {
                buffer_add(&rebuilt, "eurl=");
                buffer_add(&rebuilt, escaped ? value : eurl);
            } else {
                buffer_add_bytes(&rebuilt, at, length);
            }

            written = 1;
        }

        at = (*end == '\0') ? end : end + 1;
    }

    free(value);

    *out = buffer_take(&rebuilt);

    return (*out != NULL) ? DIMS_SIGN_OK : DIMS_SIGN_MEMORY;
}

dims_sign_status
dims_sign_dims5_eurl_url(const char *url, const char *key, const char *prefix,
                         char **out)
{
    unsigned char aes[DIMS_SIGN_KEY_BYTES];
    url_parts parts;
    char *signed_url = NULL;
    char *image_url = NULL;
    char *eurl = NULL;
    dims_sign_status status;

    if (out == NULL || url == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    status = dims_sign_dims5_url(url, key, prefix, &signed_url);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    split_url(url, &parts);

    status = read_image_url(parts.query, &image_url);
    if (status == DIMS_SIGN_OK) {
        status = dims_sign_derive_key(key, aes);
    }
    if (status == DIMS_SIGN_OK) {
        status = dims_sign_eurl_encrypt(image_url, aes, DIMS_SIGN_EURL_GCM,
                                        &eurl);
    }
    if (status == DIMS_SIGN_OK) {
        status = swap_url_for_eurl(signed_url, eurl, 1, out);
    }

    free(signed_url);
    free(image_url);
    free(eurl);

    return status;
}

dims_sign_status
dims_sign_dims4_eurl_url(const char *url, const char *key, const char *prefix,
                         dims_sign_cipher cipher, char **out)
{
    unsigned char aes[DIMS_SIGN_KEY_BYTES];
    dims4_fields fields;
    char *signed_url = NULL;
    char *secret = NULL;
    char *eurl = NULL;
    dims_sign_status status;

    if (out == NULL || url == NULL) {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    if (key == NULL || *key == '\0') {
        return DIMS_SIGN_BAD_ARGUMENT;
    }

    status = dims_sign_dims4_url(url, key, prefix, &signed_url);
    if (status != DIMS_SIGN_OK) {
        return status;
    }

    status = read_dims4_fields(url, prefix, &fields);
    if (status != DIMS_SIGN_OK) {
        free(signed_url);
        return status;
    }

    /* This endpoint reads one derivation whatever the secret looks like. */
    secret = malloc(strlen(key) + 6);
    if (secret == NULL) {
        status = DIMS_SIGN_MEMORY;
    } else {
        memcpy(secret, "sha1:", 5);
        memcpy(secret + 5, key, strlen(key) + 1);
        status = dims_sign_derive_key(secret, aes);
    }

    if (status == DIMS_SIGN_OK) {
        status = dims_sign_eurl_encrypt(fields.image_url, aes, cipher, &eurl);
    }
    if (status == DIMS_SIGN_OK) {
        status = swap_url_for_eurl(signed_url, eurl, 0, out);
    }

    release_dims4_fields(&fields);
    free(signed_url);
    free(secret);
    free(eurl);

    return status;
}

/* -- The rest ----------------------------------------------------------- */

const char *
dims_sign_strerror(dims_sign_status status)
{
    switch (status) {
        case DIMS_SIGN_OK:
            return "ok";
        case DIMS_SIGN_MEMORY:
            return "out of memory";
        case DIMS_SIGN_BAD_ARGUMENT:
            return "a required argument is missing";
        case DIMS_SIGN_BAD_URL:
            return "cannot read the URL";
        case DIMS_SIGN_BAD_FIELD:
            return "a control character is in a signed field";
        case DIMS_SIGN_CRYPTO:
            return "libcrypto refused";
        case DIMS_SIGN_BAD_EURL:
            return "cannot read the eurl value";
    }

    return "unknown";
}

void
dims_sign_free(char *string)
{
    free(string);
}
