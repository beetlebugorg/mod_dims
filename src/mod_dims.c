/**
 * mod_dims - Dynamic Image Manipulation Service
 *
 * This module provides a webservice for dynamically manipulating
 * images.  Currently cropping, resizing, reformatting and
 * thumbnail creation are supported.
 *
 * Code Flow Logic:
 *
 *  dims_handler - called by apache, determines if request should be processed
 *    \            and does initial request setup.  
 *     dims_handle_request - validates against whitelist, client list and loads image.
 *       \
 *        dims_process_image - parses operations (resize, etc) and executes them
 *          \                  using imagemagick api. 
 *           dims_send_image - sends image to connection w/appropriate headers
 *
 * Any errors during processing will call 'dims_cleanup' which will free
 * any memory and return the 'no image' image to the connection.
 * 
 * Copyright 2009 AOL LLC 
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at 
 *         
 *         http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#define MODULE_RELEASE "$Revision: $"
#define MODULE_VERSION "3.3.28"

#include "mod_dims.h"
#include "util_md5.h"
#include "cmyk_icc.h"
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include <strings.h>
#include <scoreboard.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <curl/curl.h>

module dims_module; 

#define DIMS_CURL_SHARED_KEY "dims_curl_shared"

#define MAGICK_CHECK(func, d) \
    do {\
        if(func == MagickFalse) \
            return dims_cleanup(d, NULL, DIMS_FAILURE); \
        if(d->status == DIMS_IMAGEMAGICK_TIMEOUT) \
            return dims_cleanup(d, NULL, d->status); \
    } while(0); 

typedef struct {
    CURLSH *share;

    server_rec *s;

    apr_thread_mutex_t *share_mutex;
    apr_thread_mutex_t *dns_mutex;
} dims_curl_rec;

typedef struct {
    dims_request_rec *d;
    apr_time_t start_time;
} dims_progress_rec;

typedef struct {
    apr_uint32_t success_count;
    apr_uint32_t failure_count;
    apr_uint32_t download_timeout_count;
    apr_uint32_t imagemagick_timeout_count;
} dims_stats_rec;

dims_stats_rec *stats;
apr_shm_t *shm;
apr_hash_t *ops;

static void *
dims_create_config(apr_pool_t *p, server_rec *s)
{
    dims_config_rec *config;

    config = (dims_config_rec *) apr_pcalloc(p, sizeof(dims_config_rec));
    config->whitelist = apr_table_make(p, 5);
    config->clients = apr_hash_make(p);
    config->ignore_default_output_format = apr_table_make(p, 3);

    config->download_timeout = 3000;
    config->imagemagick_timeout = 3000;

    config->no_image_url = NULL;
    config->no_image_expire = 60;
    config->default_image_prefix = NULL;

    config->default_expire = 86400;

    config->strip_metadata = 1;
    config->optimize_resize = 0;
    config->disable_encoded_fetch = 0;
    config->default_output_format = NULL;

    config->area_size = 128 * 1024 * 1024;         //  128mb max.
    config->memory_size = 512 * 1024 * 1024;       //  512mb max.
    config->map_size = 1024 * 1024 * 1024;         // 1024mb max.
    config->disk_size = 2048UL * 1024UL * 1024UL;  // 2048mb max.

    config->curl_queue_size = 10;
    config->cache_dir = NULL;
    config->secret_key = apr_pstrdup(p,"m0d1ms");
    config->max_expiry_period= 0; // never expire

    return (void *) config;
}

static const char *
dims_config_set_whitelist(cmd_parms *cmd, void *d, int argc, char *const argv[])
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, 
            &dims_module);
    int i;

    for(i = 0; i < argc; i++) {
        char *hostname = argv[i];

        /* Remove glob character and '.' if they're on the string and set
         * the value in the hash to glob.  
         */
        if(hostname[0] == '*') {
            if(*++hostname == '.') {
                hostname++;
            }

            apr_table_setn(config->whitelist, hostname, "glob");
        } else {
            apr_table_setn(config->whitelist, argv[i], "exact");
        }
    }

    return NULL;
}

static const char *
dims_config_set_ignore_default_output_format(cmd_parms *cmd, void *d, int argc, char *const argv[])
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config,
            &dims_module);
    int i;

    for(i = 0; i < argc; i++) {
        char *format = argv[i];
        char *s = format;
        while (*s) { *s = toupper(*s); s++; }

        apr_table_setn(config->ignore_default_output_format, format, "1");
    }
    return NULL;
}

static const char *
dims_config_set_default_expire(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->default_expire = atol(arg);
    return NULL;
}

static const char *
dims_config_set_no_image_expire(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->no_image_expire = atol(arg);
    return NULL;
}

static const char *
dims_config_set_download_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->download_timeout = atol(arg);
    return NULL;
}

static const char *
dims_config_set_imagemagick_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->imagemagick_timeout = atol(arg);
    return NULL;
}

static const char *
dims_config_set_strip_metadata(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    // The default is 1, so anything other than "false" will use the default
    if(strcmp(arg, "false") == 0) {
        config->strip_metadata = 0;
    }
    else {
        config->strip_metadata = 1;
    }
    return NULL;
}

static const char *
dims_config_set_include_disposition(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    if(strcmp(arg, "true") == 0) {
        config->include_disposition = 1;
    }
    else {
        config->include_disposition = 0;
    }
    return NULL;
}

static const char *
dims_config_set_optimize_resize(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->optimize_resize = atof(arg);
    return NULL;
}

static const char *
dims_config_set_encoded_fetch(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->disable_encoded_fetch = atoi(arg);
    return NULL;
}

static const char *
dims_config_set_default_output_format(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    char *output_format = (char *) arg;
    char *s = output_format;
    while (*s) { *s = toupper(*s); s++; }
    config->default_output_format = output_format;
    return NULL;
}

static const char *
dims_config_set_client(cmd_parms *cmd, void *d, int argc, char *const argv[])
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);

    dims_client_config_rec *client_config = NULL;

    if(argc == 0) {
        return NULL;
    }

    if(argc >= 1) {
        client_config = (dims_client_config_rec *) 
                apr_pcalloc(cmd->pool, 
                            sizeof(dims_client_config_rec));

        client_config->no_image_url = NULL;
        client_config->cache_control_max_age = config->default_expire;
        client_config->edge_control_downstream_ttl = -1;
        client_config->trust_src = 0;
        client_config->min_src_cache_control = -1;
        client_config->max_src_cache_control = -1;

        switch(argc) {
            case 8:
                if(strcmp(argv[7], "-") != 0) {
                    client_config->secret_key = argv[7];
                } else {
                    client_config->secret_key = NULL;
                }
            case 7:
                if(strcmp(argv[6], "-") != 0) {
                    if(atoi(argv[6]) <= 0 && strcmp(argv[6], "0") != 0) {
                        // erroneous value
                        client_config->max_src_cache_control = -2;
                    }
                    else {
                        client_config->max_src_cache_control = atoi(argv[6]);
                    }
                }
            case 6:
                if(strcmp(argv[5], "-") != 0) {
                    if(atoi(argv[5]) <= 0 && strcmp(argv[5], "0") != 0) {
                        // erroneous value
                        client_config->min_src_cache_control = -2;
                    }
                    else {
                        client_config->min_src_cache_control = atoi(argv[5]);
                    }
                }
            case 5:
                if(strcmp(argv[4], "trust") == 0) {
                    client_config->trust_src = 1;
                }
            case 4:
                if(strcmp(argv[3], "-") != 0) {
                    client_config->edge_control_downstream_ttl = atoi(argv[3]);
                }
            case 3:
                if(strcmp(argv[2], "-") != 0) {
                    client_config->cache_control_max_age = atoi(argv[2]);
                }
            case 2:
                if(strcmp(argv[1], "-") != 0) {
                    client_config->no_image_url = argv[1];
                }
            case 1:
                client_config->id = argv[0];
        }
    }

    apr_hash_set(config->clients, argv[0], APR_HASH_KEY_STRING, client_config);

    return NULL;
}

static const char *
dims_config_set_no_image_url(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->no_image_url = (char *) arg;
    return NULL;
}

static const char *
dims_config_set_image_prefix(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->default_image_prefix = (char *) arg;

    if (strncmp(config->default_image_prefix, "https://", 8) != 0 &&
        strncmp(config->default_image_prefix, "http://", 7) != 0) {
        return "DimsDefaultImagePrefix must start with 'https://' or 'http://'";
    }

    return NULL;
}

static const char *
dims_config_set_imagemagick_disk_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->disk_size = atol(arg) * 1024 * 1024;
    
    return NULL;
}
static const char *
dims_config_set_secretkeyExpiryPeriod(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->max_expiry_period = atol(arg);
    return NULL;
}
static const char *
dims_config_set_imagemagick_area_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->area_size = atol(arg) * 1024 * 1024;
    return NULL;
}

static const char *
dims_config_set_imagemagick_map_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->map_size = atol(arg) * 1024 * 1024;
    return NULL;
}

static const char *
dims_config_set_imagemagick_memory_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->memory_size = atol(arg) * 1024 * 1024;
    return NULL;
}

static void show_time(request_rec *r, apr_interval_time_t tsecs)
{
    int days, hrs, mins, secs;

    secs = (int)(tsecs % 60);
    tsecs /= 60;
    mins = (int)(tsecs % 60);
    tsecs /= 60;
    hrs = (int)(tsecs % 24);
    days = (int)(tsecs / 24);

    ap_rprintf(r, "Uptime: ");

    if (days) ap_rprintf(r, " %d day%s", days, days == 1 ? "" : "s");
    if (hrs) ap_rprintf(r, " %d hour%s", hrs, hrs == 1 ? "" : "s");
    if (mins) ap_rprintf(r, " %d minute%s", mins, mins == 1 ? "" : "s");
    if (secs) ap_rprintf(r, " %d second%s", secs, secs == 1 ? "" : "s");

    ap_rprintf(r, "\n");
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

    while(header < (start + realsize)) {
        if(*header == ':') {
            key = apr_pstrndup(d->pool, start, header - start);
            while(*header == ' ') {
                header++;
            }
            value = apr_pstrndup(d->pool, header, start + realsize - header - 2);
            header = start + realsize;
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

/**
 * This callback is called by the MagicWand API during transformation
 * operations.  How often it's called is dependent on the operation 
 * being performed but in general it's called enough that timeout
 * resolution is close enough.  For instance this won't be called if 
 * ImageMagick is busy loading up the pixel cache.
 */
MagickBooleanType 
dims_imagemagick_progress_cb(const char *text, const MagickOffsetType offset,
                             const MagickSizeType span, void *client_data)
{
    dims_progress_rec *p = (dims_progress_rec *) client_data;

    /* Calculate, in milliseconds, how long this operation has been running. */
    apr_time_t diff = (apr_time_now() - p->start_time) / 1000;
    //long complete = (long) 100L * (offset / (span - 1));

    if(diff > p->d->config->imagemagick_timeout) {
        p->d->status = DIMS_IMAGEMAGICK_TIMEOUT;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, p->d->r, 
                "Imagemagick operation, '%s', "
                "timed out after %d ms. "
                "(max: %d), on request: %s",
                text, (int) diff, 
                (int) p->d->config->imagemagick_timeout,
                p->d->r->uri);
        return MagickFalse;
    }

    return MagickTrue;
}

/* Converts a hex character to its integer value */
char from_hex(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
char to_hex(char code) {
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str) {
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

/**
 * Fetch remote image.  If successful the MagicWand will
 * have the new image loaded.
 */
static int 
dims_fetch_remote_image(dims_request_rec *d, const char *url)
{
    dims_image_data_t image_data;
    char *fetch_url = url ? (char *) url : d->no_image_url;
    int extra_time = 0;
    apr_time_t start_time;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
            "Loading image from %s", fetch_url);

    /* Allow file:/// references for NOIMAGE urls. */
    if(url == NULL && strncmp(fetch_url, "file:///", 8) == 0) {
        char *filename = fetch_url + 7;
        apr_finfo_t finfo;
        apr_status_t status;
        apr_time_t start_time;

        /* Read image from disk. */
        start_time = apr_time_now();
        status = apr_stat(&finfo, filename, APR_FINFO_SIZE, d->pool);
        if(status != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r, 
                    "mod_dims error, 'NOIMAGE image not found at %s', "
                    "on request: %s ", filename, d->r->uri);
            return 1;
        }
        d->download_time = (apr_time_now() - start_time) / 1000;
        d->original_image_size = finfo.size;

        start_time = apr_time_now();
        if(MagickReadImage(d->wand, filename) == MagickFalse) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r, 
                    "mod_dims error, 'Failed to load NOIMAGE image from %s', "
                    "on request: %s ", filename, d->r->uri);
            return 1;
        }
        d->imagemagick_time += (apr_time_now() - start_time) / 1000;
    } else {
        CURLcode code = dims_get_image_data(d, fetch_url, &image_data);

        start_time = apr_time_now();
        if(code != 0) {
            if(image_data.data) {
                free(image_data.data);
            }

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r, 
                    "libcurl error, '%s', on request: %s ", 
                    curl_easy_strerror(code), d->r->uri);

            d->status = DIMS_FAILURE;
            d->fetch_http_status = 500;
            if(code == CURLE_OPERATION_TIMEDOUT) {
                d->status = DIMS_DOWNLOAD_TIMEOUT;
            }

            d->download_time = (apr_time_now() - start_time) / 1000;

            return 1;
        }

        d->download_time = (apr_time_now() - start_time) / 1000;

        // Don't set the fetch_http_status if we're downloading the NOIMAGE image.
        if (url != NULL) {
             d->fetch_http_status = image_data.response_code;
        }

        if(image_data.response_code != 200) {
            if(image_data.response_code == 404) {
                d->status = DIMS_FILE_NOT_FOUND;
            }

            if(image_data.data) {
                free(image_data.data);
            }
            
            return 1;
        }

        char *actual_image_data = image_data.data;

        // Ensure SVGs have the appropriate XML header.
        if (image_data.size >= 4 && strncmp(image_data.data, "<svg", 4) == 0) {
            actual_image_data = apr_pstrcat(d->pool, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n", image_data.data, NULL);
            image_data.used += 55;
        }

        start_time = apr_time_now();
        if(MagickReadImageBlob(d->wand, actual_image_data, image_data.used)
                == MagickFalse) {
            ExceptionType et;

            if(image_data.data) {
                free(image_data.data);
            } 

            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r, 
                    "ImageMagick error, '%s', on request: %s ", 
                    MagickGetException(d->wand, &et), d->r->uri);

            return 1;
        }
        d->imagemagick_time += (apr_time_now() - start_time) / 1000;

        if(d->status != DIMS_DOWNLOAD_TIMEOUT) {
            d->original_image_size = image_data.used;
        }

        free(image_data.data);
    }

    return 0;
}

static apr_status_t
dims_send_image(dims_request_rec *d) 
{
    char buf[128];
    unsigned char *blob;
    char *format;
    char *content_type;
    size_t length;
    apr_time_t start_time;
    int expire_time = 0;

    char *cache_control = NULL,
         *edge_control = NULL;

    // variables referring to the src image
    char *src_header;
    char *src_start;
    int src_len;

    char *src_max_age_str;
    int src_max_age = 0;

    int trust_src_img = 0;

    format = MagickGetImageFormat(d->wand);

    MagickResetIterator(d->wand);

    start_time = apr_time_now();
    blob = MagickGetImagesBlob(d->wand, &length);
    d->imagemagick_time += (apr_time_now() - start_time) / 1000;

    /* Set the Content-Type based on the image format. */
    content_type = apr_psprintf(d->pool, "image/%s", format);
    ap_content_type_tolower(content_type);
    ap_set_content_type(d->r, content_type);

    if(d->status == DIMS_FILE_NOT_FOUND) {
        d->r->status = HTTP_NOT_FOUND;
    } else if (d->fetch_http_status != 0) {
        d->r->status = d->fetch_http_status;
    } else if(d->status != DIMS_SUCCESS) {
        d->r->status = HTTP_INTERNAL_SERVER_ERROR;
    }

    if (blob == NULL) {
        d->r->status = HTTP_BAD_REQUEST;
    }

    if(d->status == DIMS_SUCCESS && d->fetch_http_status == 200 && d->client_config) {

        // if the src image has a cache_control header, parse out the max-age
        if(d->cache_control) {

            // Ex. max-age=3600
            src_header = d->cache_control;
            src_start = src_header;
            src_len = strlen(src_header);

            while(src_header < (src_start + src_len)) {
                if(*src_header == '=') {
                    src_header++;
                    while(*src_header == ' ') {
                        src_header++;
                    }
                    src_max_age_str = apr_pstrdup(d->pool, src_header);
                    src_max_age = atoi(src_max_age_str);
                }
                src_header++;
            }
        }

        // if we trust the src image and were able to parse its cache header
        if(d->client_config->trust_src && src_max_age > 0) {

            // if the min and max config values were valid
            if(d->client_config->min_src_cache_control >= -1 &&
                    d->client_config->max_src_cache_control >= -1) {

                // if the max-age value is between the min and max, use the src value
                if( (d->client_config->min_src_cache_control == -1 ||
                        src_max_age >= d->client_config->min_src_cache_control) && 
                        (d->client_config->max_src_cache_control == -1 ||
                        src_max_age <= d->client_config->max_src_cache_control)) {

                    trust_src_img = 1;
                }
                else { // use the client configred default
                    trust_src_img = 0;
                }
            }
            else { // invalid max/min, use defaults
                trust_src_img = 0;
            }
        }
        else { // don't trust src, and use client configured default
            trust_src_img = 0;
        }


        if(trust_src_img) {
            cache_control = apr_psprintf(d->pool, "max-age=%d, public", src_max_age);
            if(d->client_config->edge_control_downstream_ttl != -1) {
                edge_control = apr_psprintf(d->pool, "downstream-ttl=%d", src_max_age);
            }
            expire_time = src_max_age;
        }
        else {
            cache_control = apr_psprintf(d->pool, "max-age=%d, public",
                    d->client_config->cache_control_max_age);

            if(d->client_config->edge_control_downstream_ttl != -1) {
                edge_control = apr_psprintf(d->pool, "downstream-ttl=%d",
                        d->client_config->edge_control_downstream_ttl);
            }
            expire_time = d->client_config->cache_control_max_age;
        }

    } else if(d->status == DIMS_SUCCESS && d->fetch_http_status == 200) {
        expire_time = d->config->default_expire;
        cache_control = apr_psprintf(d->pool, "max-age=%d, public", expire_time);
    } else {
        expire_time = d->config->no_image_expire;
        cache_control = apr_psprintf(d->pool, "max-age=%d, public", expire_time);
    }

    if(cache_control) {
        apr_table_set(d->r->headers_out, "Cache-Control", cache_control);
    }

    if(edge_control) {
        apr_table_set(d->r->headers_out, "Edge-Control", edge_control);
    }

    if(d->filename && d->config->include_disposition) {
        char *disposition = apr_psprintf(d->pool, "inline; filename=\"%s\"", d->filename);
        apr_table_set(d->r->headers_out, "Content-Disposition", disposition);
    } else if(d->content_disposition_filename && d->send_content_disposition) {
        char *disposition = apr_psprintf(d->pool, "attachment; filename=\"%s\"", d->content_disposition_filename);
        apr_table_set(d->r->headers_out, "Content-Disposition", disposition);
    }

    if(expire_time) {
        char buf[APR_RFC822_DATE_LEN];
        apr_time_t e = apr_time_now() + ((long long) expire_time * 1000L * 1000L);
        apr_rfc822_date(buf, e);
        apr_table_set(d->r->headers_out, "Expires", buf);
    }

    if(d->status == DIMS_SUCCESS) {
        snprintf(buf, 128, "DIMS_CLIENT_%s", d->client_id);
        apr_table_set(d->r->notes, "DIMS_CLIENT", d->client_id);
        apr_table_set(d->r->subprocess_env, buf, d->client_id);
    }

    char *etag = NULL;
    if (d->etag) {
        etag = ap_md5(d->pool,
                (unsigned char *) apr_pstrcat(d->pool, d->request_hash, d->etag, NULL));
    } else if (d->last_modified) {
        etag = ap_md5(d->pool,
                (unsigned char *) apr_pstrcat(d->pool, d->request_hash, d->last_modified, NULL));
    }

    if (etag) {
        apr_table_set(d->r->headers_out, "ETag", etag);
    }

    MagickSizeType image_size = 0;
    MagickGetImageLength(d->wand, &image_size);

    if (blob != NULL) {
        char content_length[256] = "";
        snprintf(content_length, sizeof(content_length), "%zu", (size_t)image_size);
        apr_table_set(d->r->headers_out, "Content-Length", content_length);

        ap_rwrite(blob, length, d->r);
    } else {
        apr_table_set(d->r->headers_out, "Content-Length", "0");
    }

    ap_rflush(d->r);

    MagickRelinquishMemory(blob);
    MagickRelinquishMemory(format);
    DestroyMagickWand(d->wand);

    /* After the image is sent record stats about this request. */
    if(d->status == DIMS_SUCCESS) {
        apr_atomic_inc32(&stats->success_count);
    } else {
        apr_atomic_inc32(&stats->failure_count);
    }

    if(d->status == DIMS_DOWNLOAD_TIMEOUT) {
        apr_atomic_inc32(&stats->download_timeout_count);
    } else if(d->status == DIMS_IMAGEMAGICK_TIMEOUT) {
        apr_atomic_inc32(&stats->imagemagick_timeout_count);
    }

    /* Record metrics for logging. */
    snprintf(buf, 128, "%d", d->status);
    apr_table_set(d->r->notes, "DIMS_STATUS", buf);

    snprintf(buf, 128, "%ld", d->original_image_size);
    apr_table_set(d->r->notes, "DIMS_ORIG_BYTES", buf);

    snprintf(buf, 128, "%ld", d->download_time);
    apr_table_set(d->r->notes, "DIMS_DL_TIME", buf);

    snprintf(buf, 128, "%ld", (apr_time_now() - d->start_time) / 1000);
    apr_table_set(d->r->notes, "DIMS_TOTAL_TIME", buf);

    if(d->status != DIMS_DOWNLOAD_TIMEOUT && 
            d->status != DIMS_IMAGEMAGICK_TIMEOUT) {
        snprintf(buf, 128, "%ld", d->imagemagick_time);
        apr_table_set(d->r->notes, "DIMS_IM_TIME", buf);
    }

    return OK;
}

static apr_status_t 
dims_cleanup(dims_request_rec *d, char *err_msg, int status)
{
    if(status != DIMS_IGNORE) {
        d->status = status;
    }

    if(d->wand) {
        ExceptionType type;
        char *msg = MagickGetException(d->wand, &type);

        if(type != UndefinedException && msg) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r, 
                    "Imagemagick error, '%s', on request: %s ", 
                    msg, d->r->uri);
        }

        MagickRelinquishMemory(msg);
        DestroyMagickWand(d->wand);
    } 
    
    if(err_msg) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r, 
                "mod_dims error, '%s', on request: %s ", 
                err_msg, d->r->uri);
    }

    if(d->no_image_url) {
        d->wand = NewMagickWand();
        if(!dims_fetch_remote_image(d, NULL)) {
            return dims_send_image(d);
        } 
        DestroyMagickWand(d->wand);
    }
    if ( status != DIMS_SUCCESS ) {
        return HTTP_NOT_FOUND;
    }
    else {
     return DECLINED;   
    }
     
}

/**
 * Parse through the requested commands and set
 * the optimal image size on the MagicWand.
 *
 * This is used while reading an image to improve
 * performance when generating thumbnails from very
 * large images.
 *
 * An example speed is taking 1817x3000 sized image and
 * reducing it to a 78x110 thumbnail:
 *
 *   without MagickSetSize: 396ms
 *   with MagickSetSize:    105ms
 */
static void
dims_set_optimal_geometry(dims_request_rec *d)
{
    MagickStatusType flags;
    RectangleInfo rec;
    const char *cmds = d->unparsed_commands;

    if(!d->wand) {
        d->wand = NewMagickWand();
    }

    /* Process operations. */
    while(cmds < d->unparsed_commands + strlen(d->unparsed_commands)) {
        char *command = ap_getword(d->pool, &cmds, '/');

        if(strcmp(command, "resize") == 0 ||
            strcmp(command, "legacy_thumbnail") == 0 ||
            strcmp(command, "thumbnail") == 0) {
            char *args = ap_getword(d->pool, &cmds, '/');

            flags = ParseAbsoluteGeometry(args, &rec);
            if(flags & WidthValue && flags & HeightValue && !(flags & PercentValue)) {
                MagickSetSize(d->wand, rec.width, rec.height);
                return;
            }
        } else {
            if(strcmp(command, "") != 0) {
                ap_getword(d->pool, &cmds, '/');
            }
        }
    }
}

/**
 * This is the main code for processing images.  It will parse
 * the command string into individual commands and execute them.  
 * When it's finished it will write the content type header and
 * image data to connection and flush the connection.
 *
 * Commands should always come in pairs, the command name followed
 * by the commands arguments delimited by '/'.  Example:
 *
 *      thumbnail/78x110/quality/70
 *
 * This would first execute the thumbnail command then it would
 * set the quality of the image to 70 before writing the image
 * to the connection.
 */
static apr_status_t
dims_process_image(dims_request_rec *d) 
{
    apr_time_t start_time = apr_time_now();

    /* Hook in the progress monitor.  It gets passed a 
     * dims_progress_rec which keeps track of the start time.
     */
    dims_progress_rec *progress_rec = (dims_progress_rec *) apr_palloc(
            d->pool, sizeof(dims_progress_rec));
    progress_rec->d = d;
    progress_rec->start_time = apr_time_now();

    /* Setting the progress monitor from the MagickWand API does not
     * seem to work.  The monitor never gets called.
     */
    SetImageProgressMonitor(GetImageFromMagickWand(d->wand), dims_imagemagick_progress_cb, 
            (void *) progress_rec);

    int exc_strip_cmd = 0;

    /* Convert image to RGB from CMYK. */
    if(MagickGetImageColorspace(d->wand) == CMYKColorspace) {
        size_t number_profiles;
        char **profiles;

        profiles = MagickGetImageProfiles(d->wand, "icc", &number_profiles);
        if (number_profiles == 0) {
            MagickProfileImage(d->wand, "ICC", cmyk_icc, sizeof(cmyk_icc));
        }
        MagickProfileImage(d->wand, "ICC", rgb_icc, sizeof(rgb_icc));

        MagickRelinquishMemory((void *)profiles);
    }

    /*
     * Flip image orientation, if needed.
     */
    MagickAutoOrientImage(d->wand);

    /* Flatten images (i.e animated gif) if there's an overlay or file type is `psd`. Otherwise, pass through. */
    size_t images = MagickGetNumberImages(d->wand);
    bool should_flatten = false;

    if (images > 1) {
        const char *cmds = d->unparsed_commands;
        while(cmds < d->unparsed_commands + strlen(d->unparsed_commands)) {
            char *command = ap_getword(d->pool, &cmds, '/');

            if (strcmp(command, "watermark") == 0) {
                should_flatten = true;
                break;
            }
        }

        char *input_format = MagickGetImageFormat(d->wand);

        if (strcmp(input_format, "PSD") == 0 || strcmp(input_format, "psd") == 0) {
            should_flatten = true;
        }

        if (should_flatten) {
            for (int i = 1; i <= images - 1; i++) {
                MagickSetIteratorIndex(d->wand, i);
                MagickRemoveImage(d->wand);
            }
        }
    }

    if (images == 1 || should_flatten) {
        bool output_format_provided = false;
        const char *cmds = d->unparsed_commands;
        while(cmds < d->unparsed_commands + strlen(d->unparsed_commands)) {
            char *command = ap_getword(d->pool, &cmds, '/');

            if (strcmp(command, "format") == 0) {
                output_format_provided = true;
            }
    
            if(strlen(command) > 0) {
                char *args = ap_getword(d->pool, &cmds, '/');

                /* If the NOIMAGE image is being used for some reason then
                * we don't want to crop it.
                */
                if(d->use_no_image && 
                        (strcmp(command, "crop") == 0 ||
                        strcmp(command, "legacy_thumbnail") == 0 ||
                        strcmp(command, "legacy_crop") == 0 ||
                        strcmp(command, "thumbnail") == 0)) {
                    MagickStatusType flags;
                    RectangleInfo rec;

                    flags = ParseAbsoluteGeometry(args, &rec);

                    if(rec.width > 0 && rec.height == 0) {
                        args = apr_psprintf(d->pool, "%ld", rec.width);
                    } else if(rec.height > 0 && rec.width == 0) {
                        args = apr_psprintf(d->pool, "x%ld", rec.height);
                    } else if(rec.width > 0 && rec.height > 0) {
                        args = apr_psprintf(d->pool, "%ldx%ld", rec.width, rec.height);
                    } else {
                        return dims_cleanup(d, NULL, DIMS_BAD_ARGUMENTS);
                    }

                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
                        "Rewriting command %s to 'resize' because a NOIMAGE "
                        "image is being processed.", command);

                    command = "resize"; 
                }

                // Check if the command is present and set flag.
                if(strcmp(command, "strip") == 0) {
                    exc_strip_cmd = 1;
                }

                dims_operation_func *func =
                        apr_hash_get(ops, command, APR_HASH_KEY_STRING);
                if(func != NULL) {
                    char *err = NULL;
                    apr_status_t code;

                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
                        "Executing command %s(%s), on request %s", 
                        command, args, d->r->uri);

                    if((code = func(d, args, &err)) != DIMS_SUCCESS) {
                        return dims_cleanup(d, err, code); 
                    }
                }
            }

            MagickMergeImageLayers(d->wand, TrimBoundsLayer);
        }

        // Set output format if not provided in the request.
        if (!output_format_provided && d->config->default_output_format) {
            char *input_format = MagickGetImageFormat(d->wand);

            if (!apr_table_get(d->config->ignore_default_output_format, input_format)) {
                char *err = NULL;
                apr_status_t code;

                if((code = dims_format_operation(d, d->config->default_output_format, &err)) != DIMS_SUCCESS) {
                    return dims_cleanup(d, err, code);
                }
            }
        }
    }

    /*
     * If the strip command was not executed from the loop, call it anyway with NULL args
     */
    if(!exc_strip_cmd) {
        dims_operation_func *strip_func = apr_hash_get(ops, "strip", APR_HASH_KEY_STRING);
        if(strip_func != NULL) {
            char *err = NULL;
            apr_status_t code;

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
                "Executing default strip command, on request %s", d->r->uri);

            if((code = strip_func(d, NULL, &err)) != DIMS_SUCCESS) {
                return dims_cleanup(d, err, code);
            }
        }        
    }

    d->imagemagick_time += (apr_time_now() - start_time) / 1000;

    /* Disable timeouts at this point since the only thing left
     * to do is save the image. 
     */
    SetImageProgressMonitor(GetImageFromMagickWand(d->wand), NULL, NULL);

    return dims_send_image(d);
}

static apr_status_t
dims_handle_request(dims_request_rec *d)
{
    apr_time_t now_time;
    d->wand = NewMagickWand();

    /* Check to make sure the client id is valid. */
    if(*d->unparsed_commands == '/') {
        d->unparsed_commands++;
    }

    d->client_id = ap_getword(d->pool, (const char **) &d->unparsed_commands, '/');

    if(!(d->client_config = 
            apr_hash_get(d->config->clients, d->client_id, APR_HASH_KEY_STRING))) {
        return dims_cleanup(d, "Application ID is not valid", DIMS_BAD_CLIENT);
    }

    if(d->client_config && d->client_config->no_image_url) {
        d->no_image_url = d->client_config->no_image_url;
    }

    now_time = apr_time_now();
    if ( d->use_secret_key == 1 ) {
        char *hash;
        char *expires_str;
        long expires;
        char *gen_hash;
        long now;
        hash = ap_getword(d->pool, (const char**)&d->unparsed_commands,'/');
        expires_str = ap_getword(d->pool, (const char**)&d->unparsed_commands,'/');
        expires = atol( expires_str);
        now = apr_time_sec(now_time);
        if ( expires - now < 0 ) {
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG,0, d->r, "Image expired: %s now=%ld", d->r->uri,now);
            return dims_cleanup( d, "Image Key has expired", DIMS_BAD_URL);
        }
        if ( expires - now > d->config->max_expiry_period && d->config->max_expiry_period >0 ) {
            ap_log_rerror( APLOG_MARK, APLOG_DEBUG,0, d->r, 
                "Image expiry too far in the future:%s %s now=%ld",expires_str, d->r->uri,now);
            return dims_cleanup(d, "Image key too far in the future", DIMS_BAD_URL);
        }

        // Throw all query params and their values into a hash table.
        // This is used to derive additional signature params.
        apr_hash_t *params = apr_hash_make(d->pool);

        if (d->r->args) {
            const size_t args_len = strlen(d->r->args) + 1;
            char *args = apr_pstrndup(d->r->pool, d->r->args, args_len);
            char *token;
            char *strtokstate;

            token = apr_strtok(args, "&", &strtokstate);
            while (token) {
                char *param = strtok(token, "=");
                apr_hash_set(params, param, APR_HASH_KEY_STRING, apr_pstrdup(d->r->pool, param + strlen(param) + 1));
                token = apr_strtok(NULL, "&", &strtokstate);
            }
        }

        // Convert %20 (space) back to '+' in commands. This fixes an issue with "+" being encoded as %20 by some clients.
        char *commands = apr_pstrdup(d->r->pool, d->unparsed_commands);
        char *s = commands;
        while (*s) {
            if (*s == ' ') {
                *s = '+';
            }

            s++;
        }

        // Standard signature params.
        char *signature_params = apr_pstrcat(d->pool, expires_str, d->client_config->secret_key, commands, d->image_url, NULL);

        // Concatenate additional params.
        char *token;
        char *strtokstate;
        token = apr_strtok(apr_hash_get(params, "_keys", APR_HASH_KEY_STRING), ",", &strtokstate);
        while (token) {
            signature_params = apr_pstrcat(d->pool, signature_params, apr_hash_get(params, token, APR_HASH_KEY_STRING), NULL);
            token = apr_strtok(NULL, ",", &strtokstate);
        }

        // Hash.
        gen_hash = ap_md5(d->pool, (unsigned char *) signature_params);
        
        if(d->client_config->secret_key == NULL) {
            gen_hash[7] = '\0';
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG,0, d->r, 
                "Developer key not set for client '%s'", d->client_config->id);
            return dims_cleanup(d, "Missing Developer Key", DIMS_BAD_URL);
        } else if (strncasecmp(hash, gen_hash, 6) != 0) {
            gen_hash[7] = '\0';
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG,0, d->r, 
                "Key Mismatch: wanted %6s got %6s [%s?url=%s]", gen_hash, hash, d->r->uri, d->image_url);
            return dims_cleanup(d, "Key mismatch", DIMS_BAD_URL);
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
            "secret key (%s) to validated (%s:%s)", hash,  d->unparsed_commands,d->image_url);    
    }

    d->request_hash = ap_md5(d->pool,
            (unsigned char *) apr_pstrcat(d->pool, d->client_id,
                d->unparsed_commands, d->image_url, NULL));
  
    dims_set_optimal_geometry(d);

    if (d->image_url && *d->image_url == '/') {
        request_rec *sub_req = ap_sub_req_lookup_uri(d->image_url, d->r, NULL);

        if (d->config->default_image_prefix != NULL) {
            d->image_url = apr_pstrcat(d->r->pool, d->config->default_image_prefix, d->image_url, NULL);
        } else if (sub_req && sub_req->canonical_filename) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Looking up image locally: %s", sub_req->canonical_filename);
            d->filename = sub_req->canonical_filename;
        } else {
            const char *req_server;
            char *req_port;
            int port;

            port = ap_get_server_port(d->r);
            req_server = ap_get_server_name_for_url(d->r);
            req_port = ap_is_default_port(port, d->r) ? "" : apr_psprintf(d->r->pool, ":%u", port);

            d->image_url = apr_psprintf(d->r->pool, "%s://%s%s%s",
                                       (char *) ap_http_scheme(d->r), req_server, req_port, d->image_url);

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Expanded relative URI to fully qualified URL since no local file existed: %s", d->image_url);
        }
    }

    if(d->filename) {
        /* Handle local images. */

        apr_finfo_t finfo;
        apr_status_t status;
        apr_time_t start_time;

        /* Read image from disk. */
        start_time = apr_time_now();
        status = apr_stat(&finfo, d->filename, APR_FINFO_SIZE, d->pool);
        if(status != 0) {
            return dims_cleanup(d, "Unable to stat image file", DIMS_FILE_NOT_FOUND);
        }
        d->download_time = (apr_time_now() - start_time) / 1000;
        d->original_image_size = finfo.size;

        start_time = apr_time_now();
        MAGICK_CHECK(MagickReadImage(d->wand, d->filename), d);
        d->imagemagick_time += (apr_time_now() - start_time) / 1000;

        return dims_process_image(d);
    } else if(d->image_url || d->no_image_url) {
        /* Handle remote images. */

        char *fetch_url = NULL;

        char *hostname, *state = "exact";
        apr_uri_t uri;
        int found = 0, done = 0;

        /* Check to make sure the URLs hostname is in the whitelist.  Wildcards
         * are handled by repeatedly checking the hash for a match after removing
         * each part of the hostname until a match is found.  If a match is found
         * and it's value is set to "glob" the match will be accepted.
         */
        if(apr_uri_parse(d->pool, d->image_url, &uri) != APR_SUCCESS) {
            return dims_cleanup(d, "Invalid URL in request.", DIMS_BAD_URL);
        }

        char *filename = strrchr(uri.path, '/');
        if (!filename || !uri.hostname) {
            return dims_cleanup(d, "Invalid URL in request.", DIMS_BAD_URL);
        }

        if (*filename == '/') {
            d->filename = ++filename;
        }

        hostname = uri.hostname;
        if ( d->use_secret_key == 1 ) {
            done = found = 1;
        }
        while(!done) {
            char *value = (char *) apr_table_get(d->config->whitelist, hostname);
            if(value && strcmp(value, state) == 0) {
                done = found = 1;
            } else {
                hostname = strstr(hostname, ".");
                if(!hostname) {
                    done = 1;
                } else {
                    hostname++;
                }
                state = "glob";
            }
        }

        if(found) {
            fetch_url = d->image_url;
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r, 
                    "Requested URL has hostname that is not in the "
                    "whitelist. (%s)", uri.hostname);
            return dims_cleanup(d, NULL, DIMS_HOSTNAME_NOT_IN_WHITELIST);
        }

        /* Fetch the image into a buffer. */
        if(fetch_url && dims_fetch_remote_image(d, fetch_url) != 0) {
            /* If image failed to download replace it with
             * the NOIMAGE image.
             */
            if(dims_fetch_remote_image(d, NULL) != 0) {
                return DECLINED;
            }
            d->use_no_image = 1;
        }

        return dims_process_image(d);
    }

    return dims_cleanup(d, NULL, DIMS_FAILURE);
}
/**
 * dims_sizer - return the size of the image (height: X\n width: X)
 */
static apr_status_t
dims_sizer(dims_request_rec *d)
{
    apr_time_t now_time;
    
    apr_uri_t uri;
    long width, height;

    d->wand = NewMagickWand();
    now_time = apr_time_now();
    if(!d->image_url ) {
        return DECLINED;
    }
    if(apr_uri_parse(d->pool, d->image_url, &uri) != APR_SUCCESS) {
        return dims_cleanup(d, "Invalid URL in request.", DIMS_BAD_URL);
    }
    if(dims_fetch_remote_image(d, d->image_url ) != 0) {
        return dims_cleanup(d, "Unable to get image file", DIMS_FILE_NOT_FOUND);
    }
 
    width = MagickGetImageWidth(d->wand);
    height = MagickGetImageHeight(d->wand);
    DestroyMagickWand(d->wand);
    ap_set_content_type(d->r, "text/plain");
    ap_rprintf(d->r, "{\n\t\"height\": %ld,\n\t\"width\": %ld\n}", height, width );
    return OK;

}

int
aes_errors(const char *message, size_t length, void *u)
{
    request_rec *r = (request_rec *) u;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s", message);
    return 0;
}

static char *
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

/**
 * The apache handler.  Apache will call this method when a request
 * for /dims/, /dims3/, /dims4/ or an image is recieved.
 *
 * Depending on how this function is called it will do one of three
 * things:
 *
 * 1) Transform old-style request into a new-style request and 
 *    pass it along to the dims_handle_newstyle function.
 * 
 * 2) Parse out the URL and commands and pass them along
 *    to the dims_handle_newstyle function.
 *
 * 3) Load the image from the filesystem and pass it along
 *    with the commands (r->path_info) to dims_process_image.
 */
static apr_status_t 
dims_handler(request_rec *r)
{
    dims_request_rec *d = (dims_request_rec *) 
            apr_palloc(r->pool, sizeof(dims_request_rec));

    d->r = r;
    d->pool = r->pool;
    d->wand = NULL;
    d->config = (dims_config_rec *) ap_get_module_config(r->server->module_config, &dims_module);
    d->client_config = NULL;
    d->no_image_url = d->config->no_image_url;
    d->use_no_image = 0;
    d->image_url = NULL;
    d->filename = NULL;
    d->cache_control = NULL;
    d->edge_control = NULL;
    d->etag = NULL;
    d->last_modified = NULL;
    d->request_hash = NULL;
    d->status = APR_SUCCESS;
    d->fetch_http_status = 0;
    d->start_time = apr_time_now();
    d->download_time = 0;
    d->imagemagick_time = 0;
    d->use_secret_key=0;
    d->optimize_resize = d->config->optimize_resize;
    d->send_content_disposition = 0;
    d->content_disposition_filename = NULL;

    /* Set initial notes to be logged by mod_log_config. */
    apr_table_setn(r->notes, "DIMS_STATUS", "0");
    apr_table_setn(r->notes, "DIMS_ORIG_BYTES", "-");
    apr_table_setn(r->notes, "DIMS_DL_TIME", "-");
    apr_table_setn(r->notes, "DIMS_IM_TIME", "-");

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
            "Handler %s : %s", r->handler, r->uri);
    /* Handle old-style DIMS parameters. */
    if(strcmp(r->handler, "dims-local") == 0 &&
            (r->path_info && strlen(r->path_info) != 0)) {
        /* Handle local filesystem images w/DIMS parameters. */
        d->filename = r->canonical_filename;
        d->unparsed_commands = r->path_info;

        return dims_handle_request(d);
    } else if(r->uri && strncmp(r->uri, "/dims/", 6) == 0) {
        int status = 0;
        char appid[50], b[10], w[10], h[10], q[10];
        char *fixed_url, *url;

        /* Translate provided parameters into new-style parameters. */
        b[0] = w[0] = h[0] = q[0] = '-';
        status = sscanf(r->uri + 5, 
                "/%49[^/]/%9[^/]/%9[^/]/%9[^/]/%9[^/]/", 
                (char *) &appid, (char *) &b, (char *) &w, (char *) &h, 
                (char *) &q);

        if(status != 5) {
            return dims_cleanup(d, NULL, DIMS_BAD_URL);
        }

        int bitmap    = (b[0] != '-') ? atoi(b) : -1;
        double width  = (w[0] != '-') ? atof(w) : 0;
        double height = (h[0] != '-') ? atof(h) : 0;
        int quality   = (q[0] != '-') ? atoi(q) : 0;

        if(bitmap == -1) {
            return dims_cleanup(d, NULL, DIMS_BAD_URL);
        }

        /* HACK: If URL has "http:/" instead of "http://", correct it. */
        url = strstr(r->uri, "http:/");
        if(url && *(url + 6) != '/') {
            fixed_url = apr_psprintf(r->pool, "http://%s", url + 6);
        } else if(!url) {
            return dims_cleanup(d, NULL, DIMS_BAD_URL);
        } else {
            fixed_url = url;
        }

        char *commands = apr_psprintf(r->pool, "%s", appid);

        if(bitmap & LEGACY_DIMS_RESIZE && bitmap & LEGACY_DIMS_CROP) {
            if(!width && !height) {
                return dims_cleanup(d, NULL, DIMS_BAD_ARGUMENTS);
            }
            commands = apr_psprintf(r->pool, "%s/legacy_thumbnail/%ldx%ld", 
                    commands, (long) width, (long) height);
        } else if(bitmap & LEGACY_DIMS_CROP || bitmap & LEGACY_DIMS_RESIZE) {
            char *cmd = (bitmap & LEGACY_DIMS_RESIZE) ? "resize" : "legacy_crop";

            if(width && !height) {
                commands = apr_psprintf(r->pool, "%s/%s/%ld", 
                        commands, cmd, (long) width);
            } else if(height && !width) {
                commands = apr_psprintf(r->pool, "%s/%s/x%ld", 
                        commands, cmd, (long) height);
            } else if(width && height) {
                commands = apr_psprintf(r->pool, "%s/%s/%ldx%ld", 
                        commands, cmd, (long) width, (long) height);
            } else {
                return dims_cleanup(d, NULL, DIMS_BAD_ARGUMENTS);
            }
        }

        if(bitmap & LEGACY_DIMS_JPG) {
            commands = apr_psprintf(r->pool, "%s/format/jpg", 
                    commands);
        } else if(bitmap & LEGACY_DIMS_PNG) {
            commands = apr_psprintf(r->pool, "%s/format/png", 
                    commands);
        } else if(bitmap & LEGACY_DIMS_GIF) {
            commands = apr_psprintf(r->pool, "%s/format/gif", 
                    commands);
        }

        if(bitmap & LEGACY_DIMS_SHARPEN) {
            commands = apr_psprintf(r->pool, "%s/sharpen/0.0x1.5", 
                    commands);
        }

        if(quality > 0 && quality <= 100) {
            commands = apr_psprintf(r->pool, "%s/quality/%d", 
                    commands, quality);
        }

        /* Locate pointer to the image URL. */
        d->image_url = fixed_url;
        d->unparsed_commands = commands;

        return dims_handle_request(d);
    } else if ((strcmp(r->handler, "dims3") == 0) ||
            (r->uri && strncmp(r->uri, "/dims3/", 7) == 0) ||
            (strcmp(r->handler, "dims4") == 0 )) {
        /* Handle new-style DIMS parameters. */
        char *p, *url = NULL, *fixed_url = NULL, *commands = NULL, *eurl = NULL;
        if (( strcmp( r->handler,"dims4") == 0)) {
               d->use_secret_key = 1;
        }

        char *unparsed_commands = apr_pstrdup(r->pool, r->uri + 7);
        d->client_id = ap_getword(d->pool, (const char **) &unparsed_commands, '/');

        if(!(d->client_config =
                apr_hash_get(d->config->clients, d->client_id, APR_HASH_KEY_STRING))) {
            return dims_cleanup(d, "Application ID is not valid", DIMS_BAD_CLIENT);
        }

        /* Check first if URL is passed as a query parameter. */
        if(r->args) {
            const size_t args_len = strlen(r->args) + 1;
            char *args = apr_pstrndup(d->r->pool, d->r->args, args_len);
            char *token;
            char *strtokstate;
            token = apr_strtok(args, "&", &strtokstate);
            while (token) {
                if(strncmp(token, "url=", 4) == 0) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "ARG: %s", token);
                    fixed_url = apr_pstrdup(r->pool, token + 4);
                    ap_unescape_url(fixed_url);

                    if (strcmp(fixed_url, "") == 0) {
                        return dims_cleanup(d, NULL, DIMS_BAD_URL);
                    }
                } else if (strncmp(token, "download=1", 10) == 0) {
                    d->send_content_disposition = 1;

                } else if (strncmp(token, "eurl=", 4) == 0) {
                    eurl = apr_pstrdup(r->pool, token + 5);

                    unsigned char *encrypted_text = apr_palloc(r->pool, apr_base64_decode_len(eurl));
                    int encrypted_length = apr_base64_decode((char *) encrypted_text, eurl);

                    // Hash secret via SHA-1.
                    unsigned char *secret = (unsigned char *) d->client_config->secret_key;
                    unsigned char hash[SHA_DIGEST_LENGTH];
                    SHA1(secret, strlen((char *) secret), hash);

                    // Convert to hex.
                    char hex[SHA_DIGEST_LENGTH * 2 + 1];
                    if (apr_escape_hex(hex, hash, SHA_DIGEST_LENGTH, 0, NULL) != APR_SUCCESS) {
                        return dims_cleanup(d, NULL, DIMS_BAD_ARGUMENTS);
                    }

                    // Use first 16 bytes.
                    unsigned char key[17];
                    strncpy((char *) key, hex, 16);
                    key[16] = '\0';

                    // Force key to uppercase
                    unsigned char *s = key;
                    while (*s) { *s = toupper(*s); s++; }

                    fixed_url = aes_128_decrypt(r, key, encrypted_text, encrypted_length);
                    if (fixed_url == NULL) {
                        return dims_cleanup(d, "URL Description Failed", DIMS_FAILURE);
                    }

                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Decrypted URL: %s", fixed_url);
                    break;

                } else if (strncmp(token, "optimizeResize=", 4) == 0) {
                    d->optimize_resize = atof(token + 15);
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Overriding optimize resize: %f", d->optimize_resize);
                }
                token = apr_strtok(NULL, "&", &strtokstate);
            }
        }

        /* Parse out URL to image.
         * HACK: If URL has "http:/" instead of "http://", correct it. 
         */
        commands = apr_pstrdup(r->pool, r->uri);
        if(fixed_url == NULL) {
            url = strstr(r->uri, "http:/");
            if(url && *(url + 6) != '/') {
                fixed_url = apr_psprintf(r->pool, "http://%s", url + 6);
            } else if(!url) {
                return dims_cleanup(d, NULL, DIMS_BAD_URL);
            } else {
                fixed_url = url;
            }

            /* Strip URL off URI.  This leaves only the tranformation parameters. */
            p = strstr(commands, "http:/");
            if(!p) return dims_cleanup(d, NULL, DIMS_BAD_URL);
            *p = '\0';
        }

        // Convert '+' in the fixed_url to ' '.
        char *image_url = apr_pstrdup(d->r->pool, fixed_url);
        char *s = image_url;
        while (*s) {
            if (*s == '+') {
                *s = ' ';
            }

            s++;
        }

        d->image_url = image_url;
        d->unparsed_commands = commands + 6;

        /* Calculate image filename for use with content disposition. */
        apr_uri_t uri;
        if (apr_uri_parse(r->pool, d->image_url, &uri) == APR_SUCCESS) {
            if (!uri.path) {
                return dims_cleanup(d, NULL, DIMS_BAD_URL);
            }

            const char *path = apr_filepath_name_get(uri.path);
            d->content_disposition_filename = apr_pstrdup(d->r->pool, path);
        }

        return dims_handle_request(d);
    } else if(strcmp(r->handler, "dims-status") == 0) {
        apr_time_t uptime;

        ap_set_content_type(r, "text/plain");
        ap_rvputs(r, "ALIVE\n\n", NULL);

        uptime = (apr_uint32_t) apr_time_sec(apr_time_now() -
                ap_scoreboard_image->global->restart_time);

        show_time(r, uptime);

        ap_rprintf(r, "Restart time: %s\n", 
                ap_ht_time(r->pool,
                ap_scoreboard_image->global->restart_time,
                "%A, %d-%b-%Y %H:%M:%S %Z", 0));

        ap_rprintf(r, "\nmod_dims version: %s (%s)\n", MODULE_VERSION, MODULE_RELEASE);
        ap_rprintf(r, "ImageMagick version: %s\n", GetMagickVersion(NULL));
        ap_rprintf(r, "libcurl version: %s\n", curl_version());

        ap_rprintf(r, "\nDetails\n-------\n");
        
        ap_rprintf(r, "Successful requests: %d\n", 
                apr_atomic_read32(&stats->success_count));
        ap_rprintf(r, "Failed requests: %d\n\n", 
                apr_atomic_read32(&stats->failure_count));
        ap_rprintf(r, "Download timeouts: %d\n", 
                apr_atomic_read32(&stats->download_timeout_count));
        ap_rprintf(r, "Imagemagick Timeouts: %d\n", 
                apr_atomic_read32(&stats->imagemagick_timeout_count));

        ap_rflush(r);
        return OK;
    } else if(strcmp(r->handler, "dims-sizer") == 0) {
        char *url, *fixed_url;
        url = strstr(r->uri, "http:/");
        if(url && *(url + 6) != '/') {
            fixed_url = apr_psprintf(r->pool, "http://%s", url + 6);
        } else if(!url) {
            return dims_cleanup(d, NULL, DIMS_BAD_URL);
        } else {
            fixed_url = url;
        }
        d->image_url = fixed_url;
        d->unparsed_commands = NULL;


        return dims_sizer(d);
    }

    return DECLINED;
}

static int
dims_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t* ptemp, server_rec *s)
{
    dims_config_rec *config = (dims_config_rec *) 
            ap_get_module_config(s->module_config, &dims_module);
    apr_status_t status;
    apr_size_t retsize;

    ap_add_version_component(p, "mod_dims/" MODULE_VERSION);

    MagickWandGenesis();
    MagickSetResourceLimit(AreaResource, config->area_size);
    MagickSetResourceLimit(DiskResource, config->disk_size);
    MagickSetResourceLimit(MemoryResource, config->memory_size);
    MagickSetResourceLimit(MapResource, config->map_size);

    ops = apr_hash_make(p);
    apr_hash_set(ops, "strip", APR_HASH_KEY_STRING, dims_strip_operation);
    apr_hash_set(ops, "resize", APR_HASH_KEY_STRING, dims_resize_operation);
    apr_hash_set(ops, "crop", APR_HASH_KEY_STRING, dims_crop_operation);
    apr_hash_set(ops, "thumbnail", APR_HASH_KEY_STRING, dims_thumbnail_operation);
    apr_hash_set(ops, "legacy_thumbnail", APR_HASH_KEY_STRING, dims_legacy_thumbnail_operation);
    apr_hash_set(ops, "legacy_crop", APR_HASH_KEY_STRING, dims_legacy_crop_operation);
    apr_hash_set(ops, "quality", APR_HASH_KEY_STRING, dims_quality_operation);
    apr_hash_set(ops, "sharpen", APR_HASH_KEY_STRING, dims_sharpen_operation);
    apr_hash_set(ops, "format", APR_HASH_KEY_STRING, dims_format_operation);
    apr_hash_set(ops, "brightness", APR_HASH_KEY_STRING, dims_brightness_operation);
    apr_hash_set(ops, "flipflop", APR_HASH_KEY_STRING, dims_flipflop_operation);
    apr_hash_set(ops, "sepia", APR_HASH_KEY_STRING, dims_sepia_operation);
    apr_hash_set(ops, "grayscale", APR_HASH_KEY_STRING, dims_grayscale_operation);
    apr_hash_set(ops, "autolevel", APR_HASH_KEY_STRING, dims_autolevel_operation);
    apr_hash_set(ops, "rotate", APR_HASH_KEY_STRING, dims_rotate_operation);
    apr_hash_set(ops, "invert", APR_HASH_KEY_STRING, dims_invert_operation);
    apr_hash_set(ops, "watermark", APR_HASH_KEY_STRING, dims_watermark_operation);

    /* Init APR's atomic functions */
    status = apr_atomic_init(p);
    if (status != APR_SUCCESS)
        return HTTP_INTERNAL_SERVER_ERROR;

    /* If there was a memory block already assigned, destroy it */
    if (shm) {
        status = apr_shm_destroy(shm);
        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mod_dims : Couldn't destroy old memory block\n");
            return status;
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "mod_dims : Old Shared memory block, destroyed.");
        }
    }

    /* Create shared memory block */
    status = apr_shm_create(&shm, sizeof(dims_stats_rec), NULL, p);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_dims : Error creating shm block\n");
        return status;
    }

    /* Check size of shared memory block */
    retsize = apr_shm_size_get(shm);
    if (retsize != sizeof(dims_stats_rec)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_dims : Error allocating shared memory block\n");
        return status;
    }

    /* Init shm block */
    stats = apr_shm_baseaddr_get(shm);
    if (stats == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_dims : Error creating status block.\n");
        return status;
    }
    memset(stats, 0, retsize);

    if (retsize < sizeof(dims_stats_rec)) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                     "mod_dims : Not enough memory allocated!! Giving up");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    stats->success_count = 1;
    stats->failure_count = 0;
    stats->download_timeout_count = 0;
    stats->imagemagick_timeout_count = 0;

    return OK;
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

static apr_status_t
dims_child_cleanup(void *data)
{
    dims_curl_rec *locks = (dims_curl_rec *) data;

    curl_share_cleanup(locks->share);
    curl_global_cleanup();

    apr_thread_mutex_destroy(locks->share_mutex);
    apr_thread_mutex_destroy(locks->dns_mutex);

    apr_pool_userdata_set(NULL, DIMS_CURL_SHARED_KEY, NULL,
            locks->s->process->pool);

    MagickWandTerminus();

    return APR_SUCCESS;
}

static void
dims_child_init(apr_pool_t *p, server_rec *s)
{
    MagickWandGenesis();
    curl_global_init(CURL_GLOBAL_ALL);

    dims_curl_rec *locks =
            (dims_curl_rec *) apr_pcalloc(p, sizeof(dims_curl_rec));

    locks->s = s;
    locks->share = curl_share_init(); 

    apr_thread_mutex_create(&locks->share_mutex, APR_THREAD_MUTEX_DEFAULT, p);
    apr_thread_mutex_create(&locks->dns_mutex, APR_THREAD_MUTEX_DEFAULT, p);

    curl_share_setopt(locks->share, CURLSHOPT_LOCKFUNC, lock_share); 
    curl_share_setopt(locks->share, CURLSHOPT_UNLOCKFUNC, unlock_share); 
    curl_share_setopt(locks->share, CURLSHOPT_USERDATA, (void *) locks); 
    curl_share_setopt(locks->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);

    /* We have to associate our handle/locks with the process->pool otherwise
     * we won't be able to get at it from the remote_fetch_image function.  This
     * pool doesn't seem to go away when the child process goes away so we
     * have to register the clean up method below.
     */
    apr_pool_userdata_set(locks, DIMS_CURL_SHARED_KEY, NULL, s->process->pool);

    /* Register cleanup with the 'p' pool so we can clean up the locks and
     * shared curl handle when this process dies.
     */
    apr_pool_cleanup_register(p, locks, dims_child_cleanup, dims_child_cleanup);
}

static void 
dims_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(dims_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(dims_child_init, NULL, NULL,APR_HOOK_MIDDLE); 
    ap_hook_handler(dims_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec dims_commands[] = 
{
    AP_INIT_TAKE_ARGV("DimsAddWhitelist",
                      dims_config_set_whitelist, NULL, RSRC_CONF,
                      "Add whitelist hostname for DIMS URL requests."),
    AP_INIT_TAKE_ARGV("DimsAddClient",
                      dims_config_set_client, NULL, RSRC_CONF,
                      "Add a client with optional no image url, max-age and downstream-ttl settings."),
    AP_INIT_TAKE_ARGV("DimsIgnoreDefaultOutputFormat",
                      dims_config_set_ignore_default_output_format, NULL, RSRC_CONF,
                      "Add input formats that shouldn't be converted to the default output format."),
    AP_INIT_TAKE1("DimsDefaultImageURL",
                  dims_config_set_no_image_url, NULL, RSRC_CONF,
                  "Default image if processing fails or original image doesn't exist."),
    AP_INIT_TAKE1("DimsDefaultImagePrefix",
                  dims_config_set_image_prefix, NULL, RSRC_CONF,
                  "Default image prefix if URL is relative."),
    AP_INIT_TAKE1("DimsCacheExpire",
                  dims_config_set_default_expire, NULL, RSRC_CONF,
                  "Default expire time for Cache-Control/Expires/Edge-Control headers, in seconds."
                  "The default is 86400"),
    AP_INIT_TAKE1("DimsNoImageCacheExpire",
                  dims_config_set_no_image_expire, NULL, RSRC_CONF,
                  "Default expire time for Cache-Control/Expires/Edge-Control headers for NOIMAGE image, in seconds."
                  "The default is 60"),
    AP_INIT_TAKE1("DimsDownloadTimeout",
                  dims_config_set_download_timeout, NULL, RSRC_CONF,
                  "Timeout for downloading remote images."
                  "The default is 3000."),
    AP_INIT_TAKE1("DimsImagemagickTimeout",
                  dims_config_set_imagemagick_timeout, NULL, RSRC_CONF,
                  "Timeout for processing images."
                  "The default is 3000."),
    AP_INIT_TAKE1("DimsImagemagickMemorySize",
                  dims_config_set_imagemagick_memory_size, NULL, RSRC_CONF,
                  "Maximum amount of memory in megabytes to use for pixel cache."
                  "The default is 512mb."),
    AP_INIT_TAKE1("DimsImagemagickAreaSize",
                  dims_config_set_imagemagick_area_size, NULL, RSRC_CONF,
                  "Maximum amount of memory in megabytes that any one image can use."
                  "The default is 128mb."),
    AP_INIT_TAKE1("DimsImagemagickMapSize",
                  dims_config_set_imagemagick_map_size, NULL, RSRC_CONF,
                  "Maximum amount of memory map in megabytes to use for the pixel cache."
                  "The default is 1024mb."),
    AP_INIT_TAKE1("DimsImagemagickDiskSize",
                  dims_config_set_imagemagick_disk_size, NULL, RSRC_CONF,
                  "Maximum amount of disk space in megabytes to use for the pixel cache."
                  "The default is 1024mb."),
    AP_INIT_TAKE1("DimsSecretMaxExpiryPeriod",
                dims_config_set_secretkeyExpiryPeriod, NULL, RSRC_CONF,
                "How long in the future (in seconds) can the expiry date on the URL be requesting. 0 = forever"
                "The default is 0."),
    AP_INIT_TAKE1("DimsStripMetadata",
                dims_config_set_strip_metadata, NULL, RSRC_CONF,
                "Should DIMS strip the metadata from the image, true OR false."
                "The default is true."),
    AP_INIT_TAKE1("DimsIncludeDisposition",
                dims_config_set_include_disposition, NULL, RSRC_CONF,
                "Should DIMS include Content-Disposition header, true OR false."
                "The default is false."),
    AP_INIT_TAKE1("DimsOptimizeResize",
                dims_config_set_optimize_resize, NULL, RSRC_CONF,
                "Should DIMS optimize resize operations. This has a slight impact on image quality. 0 = disabled"
                "The default is 0."),
    AP_INIT_TAKE1("DimsDisableEncodedFetch",
                dims_config_set_encoded_fetch, NULL, RSRC_CONF,
                "Should DIMS encode image url before fetching it."
                "The default is 0."),
    AP_INIT_TAKE1("DimsDefaultOutputFormat",
                dims_config_set_default_output_format, NULL, RSRC_CONF,
                "Default output format if 'format' command is not present in the request."),
    {NULL}
};

module AP_MODULE_DECLARE_DATA dims_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                   /* dir config creater */
    NULL,                   /* dir merger --- default is to override */
    dims_create_config,     /* server config */
    NULL,                   /* merge server config */
    dims_commands,          /* command apr_table_t */
    dims_register_hooks     /* register hooks */
};
