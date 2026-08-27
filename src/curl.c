/*
 * Fetching a source image.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "curl.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* Converts an integer value to its hex character*/
static char to_hex(char code) {
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
static char *url_encode(char *str) {
    char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr) {
        if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~' || *pstr == ':' || *pstr == '/' || *pstr == '?' || *pstr == '=' || *pstr == '&')
            *pbuf++ = *pstr;
        else
            *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

/**
 * This callback is called by the libcurl API to write data into
 * memory as it's being downloaded.
 *
 * The memory allocated here must be freed manually as it's not
 * allocated into an apache memory pool.
 */
static size_t
dims_write_image_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
    dims_image_data_t *mem = (dims_image_data_t *) data;
    size_t realsize = size * nmemb;

    /* Allocate more memory if needed. */
    if(mem->size - mem->used <= realsize) {
        mem->size = mem->size == 0 ? realsize : (mem->size + realsize) * 1.25;
        mem->data = (char *) realloc(mem->data, mem->size);
    }

    if (mem->data) {
        memcpy(&(mem->data[mem->used]), ptr, realsize);
        mem->used += realsize;
    }

    return realsize;
}

static size_t
dims_write_header_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
    dims_request_rec *d = (dims_request_rec *) data;
    size_t realsize = size * nmemb;
    char *start = (char *) ptr;
    char *header = (char *) ptr;
    char *key = NULL, *value = NULL;

    while (header < (start + realsize)) {
        if(*header == ':') {
            key = apr_pstrndup(d->pool, start, header - start);
            while(*header == ' ') {
                header++;
            }
            value = apr_pstrndup(d->pool, header + 1, start + realsize - header - 3);
            header = start + realsize - 1;
        }
        header++;
    }

    if(key && value && strcmp(key, "Cache-Control") == 0) {
        d->cache_control = value;
    } else if(key && value && strcmp(key, "Edge-Control") == 0) {
        d->edge_control = value;
    } else if(key && value && strcmp(key, "Last-Modified") == 0) {
        d->last_modified = value;
    } else if(key && value && strcmp(key, "ETag") == 0) {
        d->etag = value;
    }

    return realsize;
}

static int
dims_curl_debug_cb(CURL *handle,
    curl_infotype type,
    char *data,
    size_t size,
    void *clientp)
{
    dims_request_rec *d = (dims_request_rec *) clientp;
    switch(type) {
        case CURLINFO_HEADER_OUT:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Curl request header data: %s ", data);
            break;
        default:
            break;
    }

    /* libcurl aborts the transfer on a non-zero return. */
    return 0;
}

CURLcode
dims_get_image_data(dims_request_rec *d, char *fetch_url, dims_image_data_t *data)
{
    CURL *curl_handle;
    CURLcode code;

    dims_image_data_t image_data;
    image_data.data = NULL;
    image_data.size = 0;
    image_data.used = 0;
    int extra_time = 0;

    /* Allow for some extra time to download the NOIMAGE image. */
    void *s = NULL;

    if (d->status == DIMS_DOWNLOAD_TIMEOUT) {
        extra_time += 500;
    }

    apr_pool_userdata_get((void *) &s, DIMS_CURL_SHARED_KEY,
            d->r->server->process->pool);

    /* Encode the fetch URL before downloading */
    if (!d->config->disable_encoded_fetch) {
        fetch_url = url_encode(fetch_url);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Encoded URL: %s ", fetch_url);
    }

    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, fetch_url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, dims_write_image_cb);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &image_data);
    curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, dims_write_header_cb);
    curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *) d);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, d->config->download_timeout + extra_time);
    curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION, dims_curl_debug_cb);
    curl_easy_setopt(curl_handle, CURLOPT_DEBUGDATA, d);

    /* Set the user agent to dims/<version> */
    if (d->config->user_agent_override != NULL && d->config->user_agent_enabled == 1) {
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, d->config->user_agent_override);
    } else if (d->config->user_agent_enabled == 1) {
        char *dims_useragent = apr_psprintf(d->r->pool, "mod_dims/%s", MODULE_VERSION);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, dims_useragent);
    }

    /* The curl shared handle allows this process to share DNS cache
     * and prevents the DNS cache from going away after every request.
     */
    if (s) {
        dims_curl_rec *locks = (dims_curl_rec *) s;
        curl_easy_setopt(curl_handle, CURLOPT_SHARE, locks->share);
    }

    code = curl_easy_perform(curl_handle);

    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &image_data.response_code);
    curl_easy_cleanup(curl_handle);

    *data = image_data;

    if (!d->config->disable_encoded_fetch) {
        free(fetch_url);
    }

    return code;
}

void 
lock_share(CURL *handle, curl_lock_data data, 
              curl_lock_access access, void *userptr)
{
    dims_curl_rec *locks = (dims_curl_rec *) userptr;       

    switch(data) {
        case CURL_LOCK_DATA_DNS:
            apr_thread_mutex_lock(locks->dns_mutex);
            break;
        default:
            apr_thread_mutex_lock(locks->share_mutex);
    }
}

void unlock_share(CURL *handle, curl_lock_data data, void *userptr) 
{
    dims_curl_rec *locks = (dims_curl_rec *) userptr;       

    switch(data) {
        case CURL_LOCK_DATA_DNS:
            apr_thread_mutex_unlock(locks->dns_mutex);
            break;
        default:
            apr_thread_mutex_unlock(locks->share_mutex);
    }
}
