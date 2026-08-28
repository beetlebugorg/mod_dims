/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "request.h"
#include "test.h"

#include <ctype.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>

const char *
dims_base_url(void)
{
    const char *from_env = getenv("DIMS_TEST_BASE_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env : "http://dims:8000";
}

const char *
dims_origin_url(void)
{
    const char *from_env = getenv("DIMS_TEST_ORIGIN_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env : "http://origin:8080";
}

static size_t
write_body(void *chunk, size_t size, size_t count, void *data)
{
    dims_response *response = (dims_response *) data;
    size_t length = size * count;
    unsigned char *grown;

    grown = realloc(response->body, response->body_len + length + 1);
    if (grown == NULL) {
        return 0;
    }

    response->body = grown;
    memcpy(response->body + response->body_len, chunk, length);
    response->body_len += length;
    response->body[response->body_len] = '\0';

    return length;
}

static size_t
write_header(void *chunk, size_t size, size_t count, void *data)
{
    dims_response *response = (dims_response *) data;
    size_t length = size * count;
    char *line = (char *) chunk;
    char *colon;
    dims_header *header;
    size_t name_len, value_len;

    colon = memchr(line, ':', length);
    if (colon == NULL) {
        /* The status line, or the blank line that ends the block. */
        return length;
    }

    name_len = (size_t) (colon - line);

    /* Skip the colon, then any leading whitespace. */
    value_len = length - name_len - 1;
    colon++;
    while (value_len > 0 && (*colon == ' ' || *colon == '\t')) {
        colon++;
        value_len--;
    }
    /* Trim the trailing CR and LF. */
    while (value_len > 0 && (colon[value_len - 1] == '\r' || colon[value_len - 1] == '\n')) {
        value_len--;
    }

    header = calloc(1, sizeof(*header));
    if (header == NULL) {
        return 0;
    }

    header->name = malloc(name_len + 1);
    header->value = malloc(value_len + 1);
    header->raw = malloc(length + 1);
    if (header->name == NULL || header->value == NULL || header->raw == NULL) {
        free(header->name);
        free(header->value);
        free(header->raw);
        free(header);
        return 0;
    }

    {
        size_t raw_len = length;
        while (raw_len > 0 && (line[raw_len - 1] == '\r' || line[raw_len - 1] == '\n')) {
            raw_len--;
        }
        memcpy(header->raw, line, raw_len);
        header->raw[raw_len] = '\0';
    }
    memcpy(header->name, line, name_len);
    header->name[name_len] = '\0';
    memcpy(header->value, colon, value_len);
    header->value[value_len] = '\0';

    header->next = response->headers;
    response->headers = header;

    return length;
}

/* Shared by both entry points. url is complete. */
static dims_response *
request_url(const char *url, const char *const *headers, size_t header_count)
{
    dims_response *response = calloc(1, sizeof(*response));
    struct curl_slist *list = NULL;
    CURL *handle;
    CURLcode code;
    size_t i;

    if (response == NULL) {
        FAIL("out of memory");
        return NULL;
    }


    handle = curl_easy_init();
    if (handle == NULL) {
        FAIL("curl_easy_init failed");
        free(response);
        return NULL;
    }

    for (i = 0; i < header_count; i++) {
        list = curl_slist_append(list, headers[i]);
    }

    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_body);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, write_header);
    curl_easy_setopt(handle, CURLOPT_HEADERDATA, response);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    /* A test asserts what the service returns, never what it redirects to. */
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L);
    if (list != NULL) {
        curl_easy_setopt(handle, CURLOPT_HTTPHEADER, list);
    }

    code = curl_easy_perform(handle);
    if (code != CURLE_OK) {
        response->transport_error = curl_easy_strerror(code);
    }
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response->status);

    curl_slist_free_all(list);
    curl_easy_cleanup(handle);

    return response;
}

dims_response *
dims_get(const char *path)
{
    char url[4096];

    snprintf(url, sizeof(url), "%s%s", dims_base_url(), path);
    return request_url(url, NULL, 0);
}
const char *
dims_header_value(const dims_response *response, const char *name)
{
    const dims_header *header;

    for (header = response->headers; header != NULL; header = header->next) {
        if (strcasecmp(header->name, name) == 0) {
            return header->value;
        }
    }

    return NULL;
}

void
dims_response_free(dims_response *response)
{
    dims_header *header;

    if (response == NULL) {
        return;
    }

    header = response->headers;
    while (header != NULL) {
        dims_header *next = header->next;
        free(header->name);
        free(header->value);
        free(header->raw);
        free(header);
        header = next;
    }

    free(response->body);
    free(response);
}

char *
dims_urlencode(const char *value)
{
    CURL *handle = curl_easy_init();
    char *escaped;
    char *copy;

    if (handle == NULL) {
        return NULL;
    }

    escaped = curl_easy_escape(handle, value, 0);
    copy = (escaped != NULL) ? strdup(escaped) : NULL;

    curl_free(escaped);
    curl_easy_cleanup(handle);

    return copy;
}

const char *
dims_header_raw(const dims_response *response, const char *name)
{
    const dims_header *header;

    for (header = response->headers; header != NULL; header = header->next) {
        if (strcasecmp(header->name, name) == 0) {
            return header->raw;
        }
    }

    return NULL;
}

/* The readiness probe must not print the body it fetches. */
static size_t
discard_body(void *chunk, size_t size, size_t count, void *data)
{
    (void) chunk;
    (void) data;
    return size * count;
}

int
dims_wait_for_service(const char *url, int seconds)
{
    CURL *handle = curl_easy_init();
    int waited;

    if (handle == NULL) {
        return 1;
    }

    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 2L);
    curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, discard_body);

    for (waited = 0; waited < seconds; waited++) {
        long status = 0;

        if (curl_easy_perform(handle) == CURLE_OK) {
            curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
            if (status > 0) {
                curl_easy_cleanup(handle);
                return 0;
            }
        }
        sleep(1);
    }

    curl_easy_cleanup(handle);
    return 1;
}

dims_response *
dims_get_absolute(const char *url)
{
    return request_url(url, NULL, 0);
}

dims_response *
dims_get_with_headers(const char *path, const char *const *headers, size_t header_count)
{
    char url[4096];

    snprintf(url, sizeof(url), "%s%s", dims_base_url(), path);
    return request_url(url, headers, header_count);
}
