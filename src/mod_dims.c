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
#include "mod_dims_ops.h"
#include "configuration.h"
#include "encryption.h"
#include "curl.h"
#include "request.h"
#include "module.h"
#include "util_md5.h"
#include "cmyk_icc.h"

#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include <strings.h>

#define MAGICK_CHECK(func, d) \
    do {\
        if(func == MagickFalse) \
            return dims_cleanup(d, NULL, DIMS_FAILURE); \
        if(d->status == DIMS_IMAGEMAGICK_TIMEOUT) \
            return dims_cleanup(d, NULL, d->status); \
    } while(0); 

typedef struct {
    dims_request_rec *d;
    apr_time_t start_time;
} dims_progress_rec;

dims_stats_rec *stats;
apr_shm_t *shm;
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
        if (d->status == DIMS_BAD_URL
            || d->status == DIMS_BAD_ARGUMENTS) {
            d->r->status = HTTP_BAD_REQUEST;
        } else {
            //Includes DIMS_BAD_CLIENT, DIMS_DOWNLOAD_TIMEOUT, DIMS_IMAGEMAGICK_TIMEOUT, DIMS_HOSTNAME_NOT_IN_WHITELIST
            d->r->status = HTTP_INTERNAL_SERVER_ERROR;
        }
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

apr_status_t 
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

apr_status_t
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
            return dims_cleanup(d, "Missing Developer Key", DIMS_BAD_CLIENT);
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

void
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
