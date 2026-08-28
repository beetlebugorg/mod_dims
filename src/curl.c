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

/*
 * Appends a chunk of the download to the buffer.
 *
 * Returning anything other than the chunk size aborts the transfer, which is
 * how a failed allocation and an oversized source are reported.
 */
static size_t
dims_write_image_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
    dims_image_data_t *mem = (dims_image_data_t *) data;
    size_t realsize;
    size_t needed;

    /* size is always 1 from libcurl, but the product is still theirs to
     * define, so do not let it wrap. */
    if (size != 0 && nmemb > SIZE_MAX / size) {
        return 0;
    }
    realsize = size * nmemb;

    if (realsize > SIZE_MAX - mem->used) {
        return 0;
    }
    needed = mem->used + realsize;

    /* Zero means no limit, which is the default. */
    if (mem->max_bytes > 0 && needed > mem->max_bytes) {
        mem->exceeded_limit = 1;
        return 0;
    }

    /* One past the data, for the terminator below. */
    if (needed + 1 > mem->size) {
        size_t grown = (needed + 1) * 2;
        char *moved;

        if (mem->max_bytes > 0 && grown > mem->max_bytes + 1) {
            grown = mem->max_bytes + 1;
        }

        /* Assign only after realloc succeeds. Assigning straight into
         * mem->data loses the old pointer when it fails, which leaks the
         * buffer and leaves the caller holding NULL with a stale length. */
        moved = (char *) realloc(mem->data, grown);
        if (moved == NULL) {
            return 0;
        }

        mem->data = moved;
        mem->size = grown;
    }

    memcpy(mem->data + mem->used, ptr, realsize);
    mem->used = needed;

    /* The SVG path hands this buffer to apr_pstrcat, which reads it as a
     * string. Terminating it keeps that read inside the allocation. */
    mem->data[mem->used] = '\0';

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
    image_data.max_bytes = d->config->max_source_bytes;
    image_data.exceeded_limit = 0;
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

    /* Stop a transfer whose declared length is already over the limit,
     * before any of it is read. The write callback catches an origin that
     * declares nothing and keeps sending. */
    if (d->config->max_source_bytes > 0) {
        curl_easy_setopt(curl_handle, CURLOPT_MAXFILESIZE_LARGE,
                (curl_off_t) d->config->max_source_bytes);
    }
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

    if (image_data.exceeded_limit) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                "Source image is larger than DimsMaxSourceBytes (%" APR_SIZE_T_FMT
                " bytes), on request: %s", d->config->max_source_bytes, d->r->uri);
    }
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
