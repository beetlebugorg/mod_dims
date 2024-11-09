#ifndef _CURL_H_
#define _CURL_H

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

typedef struct {
    char *data;
    size_t size;
    size_t used;
    long response_code;
} dims_image_data_t;

CURLcode dims_get_image_data(dims_request_rec *d, char *fetch_url, dims_image_data_t *data);
void lock_share(CURL *handle, curl_lock_data data, curl_lock_access access, void *userptr);
void unlock_share(CURL *handle, curl_lock_data data, void *userptr);

#endif