/**
 * The image pipeline.
 *
 * A request arrives at handler.c, which routes it, reads its parts, and checks
 * the caller may ask for it. What happens next is here:
 *
 *  dims_fetch_remote_image  loads the source image
 *  dims_process_image       runs the commands
 *  dims_send_image          writes the response
 *
 * A failure anywhere calls dims_cleanup, which sends the error image.
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
#include "curl.h"
#include "netguard.h"
#include "status.h"
#include "pipeline.h"
#include "svgguard.h"
#include "util_md5.h"
#include "profile.h"
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include <strings.h>

#include <curl/curl.h>

/* Defined at the end of this file, declared in module.h. */




typedef struct {
    dims_request_rec *d;
    apr_time_t start_time;
} dims_progress_rec;

apr_hash_t *ops;




/*
 * Called by MagickWand during an operation, often enough to time one out.
 * ImageMagick does not call it while it loads the pixel cache.
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



/*
 * Writes Content-Disposition with the filename quoted safely.
 *
 * The filename is the last path segment of the source URL, after
 * ap_unescape_url, so it may hold a quote, a backslash, or CRLF. RFC 6266
 * gives a quoted-string, so a quote and a backslash are escaped and anything
 * outside printable ASCII is dropped.
 */
static void
dims_set_disposition(dims_request_rec *d, const char *kind, const char *filename)
{
    char safe[256];
    size_t out = 0;
    const unsigned char *in;

    for (in = (const unsigned char *) filename;
            *in != '\0' && out + 2 < sizeof(safe); in++) {
        if (*in < 0x20 || *in > 0x7E) {
            continue;
        }

        if (*in == '"' || *in == '\\') {
            safe[out++] = '\\';
        }

        safe[out++] = (char) *in;
    }
    safe[out] = '\0';

    if (out == 0) {
        return;
    }

    apr_table_set(d->r->headers_out, "Content-Disposition",
            apr_psprintf(d->pool, "%s; filename=\"%s\"", kind, safe));
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
         * How far the allowlist reaches on this fetch. The error image comes
         * from the configuration, so it skips the allowlist. Everything else
         * follows DimsAllowlistSigned. The address and protocol checks run
         * whatever this holds.
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

        /* ImageMagick's SVG renderer reads a local file named by an <image>
         * href, so refuse a source that references an external resource before
         * the renderer sees it. */
        const char *svg_reason = NULL;
        if (!dims_svg_is_safe(d->pool, image_data.data, image_data.used,
                &svg_reason)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                    "Refusing an SVG source: %s, on request: %s",
                    svg_reason, d->r->uri);
            free(image_data.data);
            d->status = DIMS_BAD_URL;
            d->fetch_http_status = HTTP_BAD_REQUEST;
            return 1;
        }

        static const char xml_header[] =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n";
        static const size_t xml_header_len = sizeof(xml_header) - 1;

        char *actual_image_data = image_data.data;
        size_t actual_image_len = image_data.used;

        /*
         * ImageMagick wants the declaration before it will read an SVG, and an
         * SVG that starts at <svg does not have one. The length comes from
         * the bytes received, never from a search for a terminator.
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

/*
 * Sets Cache-Control, Edge-Control, and Expires.
 *
 * The 200 path and the 304 path both call this, so both responses use the same
 * rules.
 */
static void
dims_set_cache_headers(dims_request_rec *d)
{
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

    if(expire_time) {
        char buf[APR_RFC822_DATE_LEN];
        apr_time_t e = apr_time_now() + ((long long) expire_time * 1000L * 1000L);
        apr_rfc822_date(buf, e);
        apr_table_set(d->r->headers_out, "Expires", buf);
    }
}

/*
 * Builds the ETag from the request hash and the origin's validator. A change
 * to the commands or to the source image changes the value.
 */
static const char *
dims_response_etag(dims_request_rec *d)
{
    if (d->etag == NULL || d->request_hash == NULL) {
        return NULL;
    }

    return apr_psprintf(d->pool, "\"%s\"",
            ap_md5(d->pool, (unsigned char *)
                    apr_pstrcat(d->pool, d->request_hash, d->etag, NULL)));
}

/* Sets ETag and Last-Modified on the response. */
static void
dims_set_validators(dims_request_rec *d)
{
    const char *etag = dims_response_etag(d);

    if (etag != NULL) {
        apr_table_set(d->r->headers_out, "ETag", etag);
    }

    if (d->last_modified != NULL) {
        apr_table_set(d->r->headers_out, "Last-Modified", d->last_modified);
    }
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

    format = MagickGetImageFormat(d->wand);

    MagickResetIterator(d->wand);

    start_time = apr_time_now();
    blob = MagickGetImagesBlob(d->wand, &length);
    d->imagemagick_time += (apr_time_now() - start_time) / 1000;

    /* Set the Content-Type based on the image format. */
    content_type = apr_psprintf(d->pool, "image/%s", format);
    ap_content_type_tolower(content_type);
    ap_set_content_type(d->r, content_type);

    /* A fetch that reached the origin reports what the origin said.
     * dims_origin_status overrides that under DimsOriginStatusMode map. */
    d->r->status = dims_origin_status(d);

    if (d->r->status == 0) {
        if (d->fetch_http_status != 0 && d->status != DIMS_FILE_NOT_FOUND) {
            d->r->status = d->fetch_http_status;
        } else {
            d->r->status = dims_http_status(d->status);
        }
    }

    if (blob == NULL) {
        d->r->status = HTTP_BAD_REQUEST;
    }

    dims_set_cache_headers(d);

    if(d->filename && d->config->include_disposition) {
        dims_set_disposition(d, "inline", d->filename);
    } else if(d->content_disposition_filename && d->send_content_disposition) {
        dims_set_disposition(d, "attachment", d->content_disposition_filename);
    }

    if(d->status == DIMS_SUCCESS) {
        snprintf(buf, 128, "DIMS_CLIENT_%s", d->client_id);
        apr_table_set(d->r->notes, "DIMS_CLIENT", d->client_id);
        apr_table_set(d->r->subprocess_env, buf, d->client_id);
    }

    dims_set_validators(d);

    /* The length written, not a second measurement of the wand.
     * MagickGetImagesBlob serializes every image; MagickGetImageLength reports
     * the current one, so a multi-frame source made the two disagree. */
    if (blob != NULL) {
        ap_set_content_length(d->r, (apr_off_t) length);

        ap_rwrite(blob, length, d->r);
    } else {
        ap_set_content_length(d->r, 0);
    }

    ap_rflush(d->r);

    MagickRelinquishMemory(blob);
    MagickRelinquishMemory(format);
    DestroyMagickWand(d->wand);
    d->wand = NULL;

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
 * Releases the wand, reporting any ImageMagick error it has.
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
 * Draws the image a failed request answers with.
 *
 * The size comes from the commands, so a page that asked for 100 by 100 gets
 * 100 by 100 and keeps its layout. A request whose size cannot be read gets a
 * square, because something has to be sent.
 */
int
dims_draw_error_image(dims_request_rec *d)
{
    static const size_t fallback = 512;
    size_t width = fallback;
    size_t height = fallback;
    PixelWand *colour;
    int ok;

    if (d->wand == NULL || d->config->error_background == NULL) {
        return 0;
    }

    /* The requested geometry, when the commands hold one. */
    if (d->commands != NULL) {
        RectangleInfo rec;
        int i;

        for (i = 0; i < d->commands->nelts; i++) {
            const dims_command *c =
                    &((const dims_command *) d->commands->elts)[i];

            if (strcmp(c->name, "resize") == 0 ||
                    strcmp(c->name, "thumbnail") == 0 ||
                    strcmp(c->name, "crop") == 0 ||
                    strcmp(c->name, "legacy_thumbnail") == 0 ||
                    strcmp(c->name, "legacy_crop") == 0) {
                memset(&rec, 0, sizeof(rec));

                if (ParseAbsoluteGeometry(c->args, &rec) != NoValue) {
                    if (rec.width > 0) {
                        width = rec.width;
                    }
                    if (rec.height > 0) {
                        height = rec.height;
                    }
                    if (rec.width > 0 && rec.height == 0) {
                        height = rec.width;
                    }
                    if (rec.height > 0 && rec.width == 0) {
                        width = rec.height;
                    }
                }
            }
        }
    }

    colour = NewPixelWand();
    if (!PixelSetColor(colour, d->config->error_background)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                "DimsErrorBackground is not a colour ImageMagick reads: %s",
                d->config->error_background);
        DestroyPixelWand(colour);
        return 0;
    }

    ok = MagickNewImage(d->wand, width, height, colour) != MagickFalse;
    DestroyPixelWand(colour);

    if (ok) {
        MagickSetImageFormat(d->wand, "PNG");
    }

    return ok;
}

/*
 * Strips the metadata from the error image, when the configuration asks for it.
 *
 * The error image does not pass through dims_process_image, which is where the
 * default strip runs, so DimsStripMetadata reaches it here.
 */
static void
dims_strip_error_image(dims_request_rec *d)
{
    if (d->config->strip_metadata) {
        MagickStripImage(d->wand);
    }
}

/*
 * Ends a failed request.
 *
 * Records the status, frees the wand, logs the reason, and sends the error
 * image when one is configured.
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

    if (d->config->error_background) {
        d->wand = NewMagickWand();

        if (dims_draw_error_image(d)) {
            dims_strip_error_image(d);
            return dims_send_image(d);
        }

        dims_free_request(d);
    } else if (d->no_image_url) {
        d->wand = NewMagickWand();
        if (!dims_fetch_remote_image(d, NULL)) {
            dims_strip_error_image(d);
            return dims_send_image(d);
        }
        dims_free_request(d);
    }

    /* With no error image to send, the status is all the caller gets. This is
     * the mapping the response writer uses. */
    if (status != DIMS_SUCCESS) {
        int mapped = dims_origin_status(d);

        return (mapped != 0) ? mapped : dims_http_status(d->status);
    }

    return DECLINED;

}

/**
 * Parse through the requested commands and set
 * the optimal image size on the MagicWand.
 *
 * ImageMagick reads at this size, which is what makes a thumbnail of a very
 * large image cheap. A 1817x3000 source down to 78x110 takes 105ms with it
 * and 396ms without.
 */
/*
 * Splits unparsed_commands into name and argument pairs, once. Every later pass
 * reads d->commands rather than walking the string again. An empty segment,
 * such as a leading or doubled slash, is skipped.
 */
void
dims_parse_commands(dims_request_rec *d)
{
    const char *cmds = d->unparsed_commands;

    d->commands = apr_array_make(d->pool, 8, sizeof(dims_command));

    if (cmds == NULL) {
        return;
    }

    while (*cmds != '\0') {
        char *name = ap_getword(d->pool, &cmds, '/');
        dims_command *command;

        if (*name == '\0') {
            continue;
        }

        command = (dims_command *) apr_array_push(d->commands);
        command->name = name;
        command->args = ap_getword(d->pool, &cmds, '/');
    }
}

void
dims_set_optimal_geometry(dims_request_rec *d)
{
    MagickStatusType flags;
    RectangleInfo rec;
    int i;

    if(!d->wand) {
        d->wand = NewMagickWand();
    }

    if (d->commands == NULL) {
        return;
    }

    for (i = 0; i < d->commands->nelts; i++) {
        const dims_command *c = &((const dims_command *) d->commands->elts)[i];

        if(strcmp(c->name, "resize") == 0 ||
            strcmp(c->name, "legacy_thumbnail") == 0 ||
            strcmp(c->name, "thumbnail") == 0) {
            flags = ParseAbsoluteGeometry(c->args, &rec);
            if(flags & WidthValue && flags & HeightValue && !(flags & PercentValue)) {
                MagickSetSize(d->wand, rec.width, rec.height);
                return;
            }
        }
    }
}


/*
 * Runs every command in the request against the wand's current image.
 *
 * Reports the first failure and the message with it. The caller ends the
 * request, because a multi-frame source runs this once per frame.
 */
static apr_status_t
dims_run_commands(dims_request_rec *d, apr_hash_t *ops, int *exc_strip_cmd,
                  int *output_format_provided, const char **err)
{
    int i;

    for (i = 0; d->commands != NULL && i < d->commands->nelts; i++) {
        const dims_command *c = &((const dims_command *) d->commands->elts)[i];
        char *command = c->name;
        char *args = c->args;
        dims_operation_func *func;

        if (strcmp(command, "format") == 0) {
            *output_format_provided = 1;
        }

        /* A NOIMAGE image must not be cropped, so a crop or a thumbnail becomes
         * a resize to the same size. */
        if (d->use_no_image &&
                (strcmp(command, "crop") == 0 ||
                strcmp(command, "legacy_thumbnail") == 0 ||
                strcmp(command, "legacy_crop") == 0 ||
                strcmp(command, "thumbnail") == 0)) {
            RectangleInfo rec;

            (void) ParseAbsoluteGeometry(args, &rec);

            if (rec.width > 0 && rec.height == 0) {
                args = apr_psprintf(d->pool, "%ld", rec.width);
            } else if (rec.height > 0 && rec.width == 0) {
                args = apr_psprintf(d->pool, "x%ld", rec.height);
            } else if (rec.width > 0 && rec.height > 0) {
                args = apr_psprintf(d->pool, "%ldx%ld", rec.width, rec.height);
            } else {
                return DIMS_BAD_ARGUMENTS;
            }

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
                "Rewriting command %s to 'resize' because a NOIMAGE "
                "image is being processed.", command);

            command = (char *) "resize";
        }

        if (strcmp(command, "strip") == 0) {
            *exc_strip_cmd = 1;
        }

        func = apr_hash_get(ops, command, APR_HASH_KEY_STRING);
        if (func != NULL) {
            apr_status_t code;

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
                "Executing command %s(%s), on request %s",
                command, args, d->r->uri);

            if ((code = func(d, args, err)) != DIMS_SUCCESS) {
                return code;
            }
        }
    }

    return DIMS_SUCCESS;
}

/*
 * Runs the commands and writes the response.
 *
 * A command is a name and its arguments, separated by a slash. The pairs run
 * in the order they appear:
 *
 *      thumbnail/78x110/quality/70
 */
apr_status_t
dims_process_image(dims_request_rec *d)
{
    apr_time_t start_time = apr_time_now();

    /* Match the request validators before the image work starts.
     * ap_meets_conditions reads ETag and Last-Modified from the response, so
     * set them first. */
    if (d->status == DIMS_SUCCESS) {
        int rc;

        dims_set_validators(d);
        rc = ap_meets_conditions(d->r);

        if (rc != OK) {
            dims_set_cache_headers(d);
            dims_free_request(d);
            apr_atomic_inc32(&stats->success_count);
            return rc;
        }
    }

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
    int output_format_provided = 0;
    const char *err = NULL;
    apr_status_t code;

    /* Convert image to RGB from CMYK. */
    if(MagickGetImageColorspace(d->wand) == CMYKColorspace) {
        const dims_profile *cmyk = dims_profile_cmyk();
        const dims_profile *rgb = dims_profile_rgb();
        size_t number_profiles;
        char **profiles;

        profiles = MagickGetImageProfiles(d->wand, "icc", &number_profiles);
        if (number_profiles == 0 && cmyk->data != NULL) {
            MagickProfileImage(d->wand, "ICC", cmyk->data, cmyk->length);
        }
        if (rgb->data != NULL) {
            MagickProfileImage(d->wand, "ICC", rgb->data, rgb->length);
        }

        /* Each name is its own allocation, and so is the array. */
        if (profiles != NULL) {
            size_t i;

            for (i = 0; i < number_profiles; i++) {
                MagickRelinquishMemory(profiles[i]);
            }
            MagickRelinquishMemory((void *) profiles);
        }
    }

    /*
     * Flip image orientation, if needed.
     */
    MagickAutoOrientImage(d->wand);

    /* Flatten images (i.e animated gif) if there's an overlay or file type is `psd`. Otherwise, pass through. */
    size_t images = MagickGetNumberImages(d->wand);
    bool should_flatten = false;

    if (images > 1) {
        int i;
        for (i = 0; d->commands != NULL && i < d->commands->nelts; i++) {
            const dims_command *c =
                    &((const dims_command *) d->commands->elts)[i];

            if (strcmp(c->name, "watermark") == 0) {
                should_flatten = true;
                break;
            }
        }

        char *input_format = MagickGetImageFormat(d->wand);

        if (input_format != NULL) {
            if (strcasecmp(input_format, "PSD") == 0) {
                should_flatten = true;
            }
            MagickRelinquishMemory(input_format);
        }

        if (should_flatten) {
            for (size_t i = 1; i < images; i++) {
                MagickSetIteratorIndex(d->wand, i);
                MagickRemoveImage(d->wand);
            }
        }
    }

    if (images == 1 || should_flatten) {
        code = dims_run_commands(d, ops, &exc_strip_cmd, &output_format_provided,
                &err);
        if (code != DIMS_SUCCESS) {
            return dims_cleanup(d, err, code);
        }
    } else if (d->config->animated_mode == DIMS_ANIMATED_TRANSFORM) {
        /*
         * A frame after the first is stored as a difference against the one
         * before it, so a command has to see the whole frame. Coalescing
         * builds those, at the cost of holding every frame in full.
         */
        MagickWand *coalesced = MagickCoalesceImages(d->wand);

        if (coalesced == NULL) {
            return dims_cleanup(d, "Unable to coalesce the source frames",
                    DIMS_FAILURE);
        }

        DestroyMagickWand(d->wand);
        d->wand = coalesced;

        SetImageProgressMonitor(GetImageFromMagickWand(d->wand),
                dims_imagemagick_progress_cb, (void *) progress_rec);

        MagickResetIterator(d->wand);
        while (MagickNextImage(d->wand) != MagickFalse) {
            code = dims_run_commands(d, ops, &exc_strip_cmd,
                    &output_format_provided, &err);
            if (code != DIMS_SUCCESS) {
                return dims_cleanup(d, err, code);
            }
        }
    }

    if (images == 1 || should_flatten ||
            d->config->animated_mode == DIMS_ANIMATED_TRANSFORM) {
        // Set output format if not provided in the request.
        if (!output_format_provided && d->config->default_output_format) {
            char *input_format = MagickGetImageFormat(d->wand);
            int use_default = input_format == NULL ||
                    !apr_table_get(d->config->ignore_default_output_format, input_format);

            MagickRelinquishMemory(input_format);

            if (use_default) {
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
