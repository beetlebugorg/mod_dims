#ifndef _CURL_H_
#define _CURL_H_

#include <stddef.h>
#include <curl/curl.h>

#include "request.h"

#define DIMS_CURL_SHARED_KEY "dims_curl_shared"

typedef struct {
    CURLSH *share;

    server_rec *s;

    apr_thread_mutex_t *share_mutex;
    apr_thread_mutex_t *dns_mutex;
} dims_curl_rec;

CURLcode dims_curl(dims_request_rec *d, const char *url, dims_image_data_t *data);

void dims_curl_init(apr_pool_t *p, server_rec *s);

#endif