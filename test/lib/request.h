/*
 * Issues a request with libcurl and returns the body and the headers.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_REQUEST_H
#define DIMS_TEST_REQUEST_H

#include <stddef.h>

typedef struct dims_header {
    char *name;
    char *value;
    /* The line as the origin sent it, minus the terminator. The leading space is
     * about whitespace a normalizing client would hide. */
    char *raw;
    struct dims_header *next;
} dims_header;

typedef struct dims_response {
    long status;
    unsigned char *body;
    size_t body_len;
    dims_header *headers;
    /* Set when the transfer itself failed, for example on a timeout. */
    const char *transport_error;
} dims_response;

/* The base URL of the service under test. Default http://dims:8000. */
const char *dims_base_url(void);

/* The base URL of the fixture origin. Default http://origin:8080. */
const char *dims_origin_url(void);

/* Issues GET against the service. path starts with a slash. */
dims_response *dims_get(const char *path);

/* The same, against a URL given in full. */
dims_response *dims_get_absolute(const char *url);

/* Issues GET with extra request headers, each "Name: value". */
dims_response *dims_get_with_headers(const char *path, const char *const *headers,
                                     size_t header_count);

/* The same, against a URL given in full. */
dims_response *dims_get_absolute_with_headers(const char *url,
                                              const char *const *headers,
                                              size_t header_count);

/* Case insensitive lookup. Returns NULL when the header is absent. */
const char *dims_header_value(const dims_response *response, const char *name);

/* The header line as received, before whitespace is trimmed. */
const char *dims_header_raw(const dims_response *response, const char *name);

void dims_response_free(dims_response *response);

/* Polls url until it answers or seconds elapse. Returns 0 when it answers. */
int dims_wait_for_service(const char *url, int seconds);

/* Percent-encodes a value for use in a query string. Caller frees. */
char *dims_urlencode(const char *value);

#endif
