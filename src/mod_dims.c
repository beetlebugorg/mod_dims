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


#include "mod_dims.h"
#include "configuration.h"
#include "encryption.h"
#include "curl.h"
#include "netguard.h"
#include "status.h"
#include "handler.h"
#include "pipeline.h"
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

/* Defined at the end of this file, declared in module.h. */

#define DIMS_POST_CONFIG_KEY "dims_post_config"



typedef struct {
    dims_request_rec *d;
    apr_time_t start_time;
} dims_progress_rec;

apr_hash_t *ops;




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



/**
 * Fetch remote image.  If successful the MagicWand will
 * have the new image loaded.
 */
int 
dims_fetch_remote_image(dims_request_rec *d, const char *url)
{
    dims_image_data_t image_data;
    char *fetch_url = url ? (char *) url : d->no_image_url;
    apr_time_t start_time;

    /*
     * Passing no URL asks for the error image, and there may not be one:
     * DimsDefaultImageURL and the per client setting are both optional.
     *
     * Nothing to fetch is a failure, not a crash. The file:/// check below
     * reads fetch_url, so without this the worker dies whenever a source
     * fetch fails on a server with no error image configured.
     */
    if (fetch_url == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
                "No error image is configured, on request: %s", d->r->uri);
        return 1;
    }
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
        CURLcode code;
        dims_net_result guard;

        /*
         * How far the allowlist reaches on this fetch.
         *
         * The error image comes from the configuration, not from the caller,
         * so the allowlist never applies to it.
         *
         * Everything else follows DimsAllowlistSigned. The default logs what
         * enforcing would refuse and lets the fetch through, which is what
         * keeps this a drop-in upgrade: a signed request has never consulted
         * the allowlist, and a redirect has never been re-checked against it.
         * The address and protocol checks below run on every fetch whatever
         * this holds.
         */
        dims_allowlist_mode mode = DIMS_ALLOWLIST_SKIP;

        if (url != NULL) {
            mode = d->config->allowlist_signed ? DIMS_ALLOWLIST_ENFORCE
                                               : DIMS_ALLOWLIST_LOG;
        }

        guard = dims_validate_image_url(d, fetch_url, mode);
        if (guard != DIMS_NET_OK) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                    "Refusing to fetch %s: %s, on request: %s",
                    fetch_url, dims_net_reason(guard), d->r->uri);

            d->status = DIMS_NETWORK_REFUSED;
            d->fetch_http_status = HTTP_BAD_REQUEST;

            return 1;
        }

        code = dims_get_image_data(d, fetch_url, &image_data, mode);

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

            /* The guard stops a transfer by failing the socket or the header
             * callback, so libcurl reports a transport error. Say what really
             * happened instead. The redirect cap is libcurl's own limit, set
             * by the guard, so it reports the same way. */
            if (code == CURLE_TOO_MANY_REDIRECTS) {
                d->net_refusal = DIMS_NET_TOO_MANY_REDIRECTS;
            }

            if (d->net_refusal != DIMS_NET_OK) {
                d->status = DIMS_NETWORK_REFUSED;
                d->fetch_http_status = HTTP_BAD_REQUEST;
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

        static const char xml_header[] =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n";
        static const size_t xml_header_len = sizeof(xml_header) - 1;

        char *actual_image_data = image_data.data;
        size_t actual_image_len = image_data.used;

        /*
         * ImageMagick wants the declaration before it will read an SVG, and
         * an SVG that starts at <svg has none.
         *
         * The length is carried rather than recomputed. This used apr_pstrcat,
         * which reads the download buffer as a string: it ran off the end of
         * the allocation looking for a terminator, and the concatenated result
         * was whatever length that search happened to find. The buffer is
         * terminated now, but the size still comes from the bytes received,
         * not from a search.
         */
        if (image_data.used >= 4 && strncmp(image_data.data, "<svg", 4) == 0) {
            actual_image_len = xml_header_len + image_data.used;
            actual_image_data = apr_palloc(d->pool, actual_image_len + 1);

            memcpy(actual_image_data, xml_header, xml_header_len);
            memcpy(actual_image_data + xml_header_len, image_data.data,
                   image_data.used);
            actual_image_data[actual_image_len] = '\0';
        }

        start_time = apr_time_now();
        if(MagickReadImageBlob(d->wand, actual_image_data, actual_image_len)
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

apr_status_t
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

    /*
     * A fetch that reached the origin reports whatever the origin said, which
     * is why an origin error becomes the caller's error. dims_http_status
     * covers the cases the module decided itself.
     */
    if (d->fetch_http_status != 0 && d->status != DIMS_FILE_NOT_FOUND) {
        d->r->status = d->fetch_http_status;
    } else if (d->status != DIMS_SUCCESS) {
        d->r->status = dims_http_status(d->status);
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
    }

    if (etag) {
        apr_table_set(d->r->headers_out, "ETag", etag);
    }

    if(d->last_modified) {
        apr_table_set(d->r->headers_out, "Last-Modified", d->last_modified);
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

/*
 * Releases the wand, reporting any ImageMagick error it carries.
 *
 * Safe to call more than once: the wand pointer is cleared, so a later call
 * has nothing to do. Several failure paths reach this twice.
 */
void
dims_free_request(dims_request_rec *d)
{
    ExceptionType type;
    char *msg;

    if (d->wand == NULL) {
        return;
    }

    msg = MagickGetException(d->wand, &type);
    if (type != UndefinedException && msg) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                "Imagemagick error, '%s', on request: %s ", msg, d->r->uri);
    }
    MagickRelinquishMemory(msg);

    DestroyMagickWand(d->wand);
    d->wand = NULL;
}

/*
 * Ends a failed request.
 *
 * Records the status, frees the wand, logs the reason, and sends the error
 * image when one is configured. The name is dims_cleanup for history; what it
 * does is send an error.
 */
apr_status_t
dims_cleanup(dims_request_rec *d, const char *err_msg, int status)
{
    if (status != DIMS_IGNORE) {
        d->status = status;
    }

    dims_free_request(d);

    if (err_msg) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                "mod_dims error, '%s', on request: %s ", err_msg, d->r->uri);
    }

    if (d->no_image_url) {
        d->wand = NewMagickWand();
        if (!dims_fetch_remote_image(d, NULL)) {
            return dims_send_image(d);
        }
        dims_free_request(d);
    }

    /*
     * With no error image to send, the status is all the caller gets, so it
     * has to be the right one. dims_http_status is the same mapping the
     * response writer uses.
     *
     * This answered 404 for every failure until now, whatever it was: a
     * malformed geometry, a timeout, an unknown application id. A 404 tells a
     * caller to stop retrying, which is wrong for a timeout, and tells a
     * developer the image is missing, which is wrong for a bad request.
     */
    if (status != DIMS_SUCCESS) {
        return dims_http_status(d->status);
    }

    return DECLINED;

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
void
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
apr_status_t
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
            for (size_t i = 1; i < images; i++) {
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
                    RectangleInfo rec;

                    (void) ParseAbsoluteGeometry(args, &rec);

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

                    command = (char *) "resize";
                }

                // Check if the command is present and set flag.
                if(strcmp(command, "strip") == 0) {
                    exc_strip_cmd = 1;
                }

                dims_operation_func *func =
                        apr_hash_get(ops, command, APR_HASH_KEY_STRING);
                if(func != NULL) {
                    const char *err = NULL;
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
                const char *err = NULL;
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
            const char *err = NULL;
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

static int
dims_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t* ptemp, server_rec *s)
{
    apr_status_t status;
    apr_size_t retsize;
    void *first_pass = NULL;

    /*
     * httpd runs post_config twice. The first pass is a dry run, and the pool
     * it hands over is cleared afterwards. That takes the shared memory with
     * it and leaves the global handle pointing at freed memory, so the second
     * pass was destroying a block that no longer existed. glibc happened to
     * report success. musl reports the error, and the server then refuses to
     * start.
     *
     * Skip the first pass, which is what httpd's own modules do. The shared
     * memory is then created once, against a pool that lives as long as the
     * server.
     */
    apr_pool_userdata_get(&first_pass, DIMS_POST_CONFIG_KEY, s->process->pool);
    if (first_pass == NULL) {
        apr_pool_userdata_set((const void *) 1, DIMS_POST_CONFIG_KEY,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    ap_add_version_component(p, "mod_dims/" MODULE_VERSION);

    /* Say which tiers of the network guard the operator left permissive, on
     * every server, so the setting is visible without reading the config. */
    {
        server_rec *server;

        for (server = s; server != NULL; server = server->next) {
            dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
                    server->module_config, &dims_module);

            if (config != NULL) {
                dims_netguard_log_configuration(server, config);
            }
        }
    }

    /*
     * ImageMagick is started in the child, never here. Starting it in the
     * parent leaves every worker inheriting semaphores and cache state across
     * the fork, which ImageMagick 7 does not survive: the first request into a
     * worker segfaults. The resource limits go with it, because they are
     * per process and the process that matters is the one doing the work.
     *
     * See dims_child_init.
     */

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



apr_status_t
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

void
dims_child_init(apr_pool_t *p, server_rec *s)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            s->module_config, &dims_module);

    MagickWandGenesis();

    /* Every limit is per process, so the total a host can use is this
     * multiplied by the number of workers. */
    MagickSetResourceLimit(AreaResource, config->area_size);
    MagickSetResourceLimit(DiskResource, config->disk_size);
    MagickSetResourceLimit(MemoryResource, config->memory_size);
    MagickSetResourceLimit(MapResource, config->map_size);
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


module AP_MODULE_DECLARE_DATA dims_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                   /* dir config creater */
    NULL,                   /* dir merger --- default is to override */
    dims_create_config,     /* server config */
    NULL,                   /* merge server config */
    dims_directives,        /* command apr_table_t */
    dims_register_hooks,    /* register hooks */
    0                       /* flags */
};
