/**
 * mod_dims - Dynamic Image Manipulation Service
 *
 * Copyright 2009 AOL LLC 
 * Copyright 2024 Jeremy Collins
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
#include "cmyk_icc.h"

#include <util_md5.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include <strings.h>
#include <openssl/sha.h>

#define MAGICK_CHECK(func, d) \
    do {\
        if(func == MagickFalse) \
            return DIMS_FAILURE; \
        if(d->status == DIMS_IMAGEMAGICK_TIMEOUT) \
            return d->status; \
    } while(0); 

typedef struct dims_progress_rec {
    dims_request_rec *d;
    apr_time_t start_time;
} dims_progress_rec;

typedef struct dims_processed_image {
    size_t length;
    unsigned char *bytes;
    char *format;
    apr_status_t error;
} dims_processed_image;

/**
 * This callback is called by the MagicWand API during transformation
 * operations.  How often it's called is dependent on the operation 
 * being performed but in general it's called enough that timeout
 * resolution is close enough.  For instance this won't be called if 
 * ImageMagick is busy loading up the pixel cache.
 */
MagickBooleanType 
dims_imagemagick_progress_cb(const char *text, 
                             const MagickOffsetType offset,
                             const MagickSizeType span, 
                             void *client_data)
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
static apr_status_t
dims_download_source_image(dims_request_rec *d, const char *url)
{
    apr_time_t start_time;
    d->source_image = apr_palloc(d->pool, sizeof(dims_image_data_t));
    d->source_image->cache_control = NULL;
    d->source_image->edge_control = NULL;
    d->source_image->last_modified = NULL;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Loading image from %s", url);

    CURLcode code = dims_curl(d, url, d->source_image);

    start_time = apr_time_now();
    if(code != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r, 
                "libcurl error, '%s', on request: %s ", 
                curl_easy_strerror(code), d->r->uri);


        if(code == CURLE_OPERATION_TIMEDOUT) {
            d->status = DIMS_DOWNLOAD_TIMEOUT;
        }

        d->download_time = (apr_time_now() - start_time) / 1000;

        return DIMS_FAILURE;
    }

    d->download_time = (apr_time_now() - start_time) / 1000;

    if(d->source_image->response_code != 200) {
        if(d->source_image->response_code == 404) {
            d->status = DIMS_FILE_NOT_FOUND;
        }

        return DIMS_FAILURE;
    }

    // Ensure SVGs have the appropriate XML header.
    if (d->source_image->size >= 4 && strncmp(d->source_image->data, "<svg", 4) == 0) {
        d->source_image->data =
            apr_pstrcat(d->pool, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n", 
                        d->source_image->data, NULL);
        d->source_image->used += 55;
    }

    return DIMS_SUCCESS;
}

static apr_status_t 
dims_status_to_http_code(dims_request_rec *d)
{
    if(d->status == DIMS_FILE_NOT_FOUND) {
        return HTTP_NOT_FOUND;
    } else if (d->source_image->response_code != 0) {
        return d->source_image->response_code;
    } else if (d->status != DIMS_SUCCESS) {
        if (d->status == DIMS_BAD_URL || d->status == DIMS_BAD_ARGUMENTS) {
            return HTTP_BAD_REQUEST;
        } else {
            //Includes DIMS_BAD_CLIENT, DIMS_DOWNLOAD_TIMEOUT, DIMS_IMAGEMAGICK_TIMEOUT, DIMS_HOSTNAME_NOT_IN_WHITELIST
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

static apr_status_t
dims_send_image(dims_request_rec *d, dims_processed_image *image)
{
    request_rec *r = d->r;

    // Set the Content-Type based on the image format.
    char *format = image->format;
    char *content_type = apr_psprintf(r->pool, "image/%s", format);
    ap_content_type_tolower(content_type);
    ap_set_content_type(r, content_type);

    // Calculate the cache control headers.
    int max_age = d->client_config->cache_control_max_age;
    int expire_time = d->client_config->cache_control_max_age;
    int downstream_ttl = d->client_config->edge_control_downstream_ttl;
    char *cache_control = NULL,
         *edge_control = NULL;

    // Use 'max-age' from the source image only if the client trusts the source,
    // and the source image has a 'max-age' that falls within the configured min and max values.
    int trust_src_img = 0;
    if (d->client_config->trust_src && d->source_image->max_age > 0) {
        int min = d->client_config->min_src_cache_control;
        int max = d->client_config->max_src_cache_control;

        if((min == -1 || d->source_image->max_age >= d->client_config->min_src_cache_control) && 
           (max == -1 || d->source_image->max_age <= d->client_config->max_src_cache_control)) {
            max_age = d->source_image->max_age;
            expire_time = d->source_image->max_age;
            downstream_ttl = d->source_image->max_age;
        }
    } 

    cache_control = apr_psprintf(d->pool, "max-age=%d, public", max_age);
    apr_table_set(d->r->headers_out, "Cache-Control", cache_control);

    if(d->client_config->edge_control_downstream_ttl != -1) {
        edge_control = apr_psprintf(d->pool, "downstream-ttl=%d", downstream_ttl);
        apr_table_set(d->r->headers_out, "Edge-Control", edge_control);
    }

    if(d->content_disposition_filename && d->send_content_disposition) {
        char *disposition = apr_psprintf(d->pool, "attachment; filename=\"%s\"", d->content_disposition_filename);
        apr_table_set(d->r->headers_out, "Content-Disposition", disposition);
    }

    if(expire_time > 0) {
        char buf[APR_RFC822_DATE_LEN];
        apr_time_t e = apr_time_now() + ((long long) expire_time * 1000L * 1000L);
        apr_rfc822_date(buf, e);
        apr_table_set(d->r->headers_out, "Expires", buf);
    }

    if(d->status == DIMS_SUCCESS) {
        char buf[128];
        snprintf(buf, 128, "DIMS_CLIENT_%s", d->client_id);
        apr_table_set(d->r->notes, "DIMS_CLIENT", d->client_id);
    }

    if (d->source_image->etag) {
        char *etag = ap_md5(d->pool, (unsigned char *) 
            apr_pstrcat(d->pool, d->request_hash, d->source_image->etag, NULL));

        apr_table_set(d->r->headers_out, "ETag", etag);
    } else if (d->source_image->last_modified) {
        char *etag = ap_md5(d->pool, (unsigned char *) 
            apr_pstrcat(d->pool, d->request_hash, d->source_image->last_modified, NULL));

        apr_table_set(d->r->headers_out, "ETag", etag);
    }

    unsigned char *blob = image->bytes;
    size_t length = image->length;
    if (blob != NULL) {
        char content_length[256] = "";
        snprintf(content_length, sizeof(content_length), "%zu", (size_t) image->length);
        apr_table_set(d->r->headers_out, "Content-Length", content_length);

        ap_rwrite(blob, length, d->r);
    } else {
        apr_table_set(d->r->headers_out, "Content-Length", "0");
    }

    return OK;
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

    /* Process operations. */
    for (int i = 0; i < d->commands_list->nelts; i++) {
        dims_command_t *cmd = &APR_ARRAY_IDX(d->commands_list, i, dims_command_t);

        if(strcmp(cmd->name, "resize") == 0 ||
            strcmp(cmd->name, "legacy_thumbnail") == 0 ||
            strcmp(cmd->name, "thumbnail") == 0) {

            flags = ParseAbsoluteGeometry(cmd->arg, &rec);
            if(flags & WidthValue && flags & HeightValue && !(flags & PercentValue)) {
                MagickSetSize(d->wand, rec.width, rec.height);
                return;
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
static dims_processed_image *
dims_process_image(dims_request_rec *d) 
{
    apr_time_t start_time = apr_time_now();

    d->wand = NewMagickWand();

    if(MagickReadImageBlob(d->wand, d->source_image->data, d->source_image->used) == MagickFalse) {
        ExceptionType et;

        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r, 
            "ImageMagick error, '%s', on request: %s ", 
            MagickGetException(d->wand, &et), d->r->uri);

        return NULL;
    }
    d->imagemagick_time += (apr_time_now() - start_time) / 1000;

    dims_processed_image *image = (dims_processed_image *) apr_palloc(d->pool, sizeof(dims_processed_image)); 

    /* Hook in the progress monitor.  It gets passed a dims_progress_rec which keeps track of the start time.  */
    dims_progress_rec *progress_rec = (dims_progress_rec *) apr_palloc(d->pool, sizeof(dims_progress_rec));
    progress_rec->d = d;
    progress_rec->start_time = apr_time_now();

    /* Setting the progress monitor from the MagickWand API does not seem to work.  The monitor never gets called.  */
    SetImageProgressMonitor(GetImageFromMagickWand(d->wand), dims_imagemagick_progress_cb, (void *) progress_rec);

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
        for (int i = 0; i < d->commands_list->nelts; i++) {
            dims_command_t *cmd = &APR_ARRAY_IDX(d->commands_list, i, dims_command_t);

            if (strcmp(cmd->name, "watermark") == 0) {
                should_flatten = true;
                break;
            }
        }

        char *input_format = MagickGetImageFormat(d->wand);

        if (strcmp(input_format, "PSD") == 0 || strcmp(input_format, "psd") == 0) {
            should_flatten = true;
        }

        if (should_flatten) {
            for (size_t i = 1; i <= images - 1; i++) {
                MagickSetIteratorIndex(d->wand, i);
                MagickRemoveImage(d->wand);
            }
        }
    }

    if (images == 1 || should_flatten) {
        bool output_format_provided = false;

        for (int i = 0; i < d->commands_list->nelts; i++) {
            dims_command_t *cmd = &APR_ARRAY_IDX(d->commands_list, i, dims_command_t);

            if (strcmp(cmd->name, "format") == 0) {
                output_format_provided = true;
            }

            if(strcmp(cmd->name, "strip") == 0) {
                exc_strip_cmd = 1;
            }

            dims_operation_func *func = dims_operation_lookup(cmd->name);
            if (func != NULL) {
                char *err = NULL;
                apr_status_t code;

                 ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
                    "Executing command %s(%s), on request %s", cmd->name, cmd->arg, d->r->uri);

                if ((code = func(d, cmd->arg, &err)) != DIMS_SUCCESS) {
                    DestroyMagickWand(d->wand);
                    image->error = code;
                    return image;
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
                    DestroyMagickWand(d->wand);
                    image->error = code;
                    return image;
                }
            }
        }
    }

    /*
     * If the strip command was not executed from the loop, call it anyway with NULL args
     */
    if(!exc_strip_cmd) {
        dims_operation_func *strip_func = dims_operation_lookup("strip");
        if(strip_func != NULL) {
            char *err = NULL;
            apr_status_t code;

            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
                "Executing default strip command, on request %s", d->r->uri);

            if((code = strip_func(d, NULL, &err)) != DIMS_SUCCESS) {
                DestroyMagickWand(d->wand);
                image->error = code;
                return image;
            }
        }        
    }

    d->imagemagick_time += (apr_time_now() - start_time) / 1000;

    /* Disable timeouts at this point since the only thing left
     * to do is save the image. 
     */
    SetImageProgressMonitor(GetImageFromMagickWand(d->wand), NULL, NULL);

    MagickResetIterator(d->wand);

    image->error = DIMS_SUCCESS;
    image->format = MagickGetImageFormat(d->wand);
    image->bytes = MagickGetImagesBlob(d->wand, &image->length);

    DestroyMagickWand(d->wand);

    return image;
}

int
verify_dims4_signature(dims_request_rec *d) {
    if(d->client_config->secret_key == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG,0, d->r, 
            "Secret key not set for client '%s'", d->client_config->id);

        return DIMS_MISSING_SECRET;
    }

    // Standard signature params.
    char *signature_params = apr_pstrcat(d->pool, 
        d->expiration, 
        d->client_config->secret_key, 
        d->commands, 
        d->image_url, 
        NULL);

    // Concatenate additional params.
    char *strtokstate = NULL;
    char *keys = apr_hash_get(d->query_params, "_keys", APR_HASH_KEY_STRING);
    if (keys != NULL) {
        char *token = apr_strtok(keys, ",", &strtokstate);
        while (token) {
            signature_params = apr_pstrcat(d->pool, signature_params, apr_hash_get(d->query_params, token, APR_HASH_KEY_STRING), NULL);
            token = apr_strtok(NULL, ",", &strtokstate);
        }
    }

    // Calculate the signature.
    char *signature = ap_md5(d->pool, (unsigned char *) signature_params);
    if (strncasecmp(d->signature, signature, 6) != 0) {
        signature[7] = '\0';

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG,0, d->r, 
            "Signature invalid: wanted %6s got %6s [%s?url=%s]", signature, d->signature, d->r->uri, d->image_url);

        return DIMS_INVALID_SIGNATURE;
    }

    return OK;
}

int
verify_dims3_allowlist(dims_request_rec *d) {
    char *hostname, *state = apr_pstrdup(d->pool, "exact");
    apr_uri_t uri;
    int found = 0, done = 0;

    /* Check to make sure the URLs hostname is in the whitelist.  Wildcards
        * are handled by repeatedly checking the hash for a match after removing
        * each part of the hostname until a match is found.  If a match is found
        * and it's value is set to "glob" the match will be accepted.
        */
    if(apr_uri_parse(d->pool, d->image_url, &uri) != APR_SUCCESS) {
        return DIMS_BAD_URL;
    }

    char *filename = strrchr(uri.path, '/');
    if (!filename || !uri.hostname) {
        return DIMS_BAD_URL;
    }

    hostname = uri.hostname;
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
            state = apr_pstrdup(d->pool, "glob");
        }
    }

    return found;
}

static apr_status_t
dims_handle_request(dims_request_rec *d)
{
    char buf[128];

    /* Set initial notes to be logged by mod_log_config. */
    apr_table_setn(d->r->notes, "DIMS_STATUS", "0");
    apr_table_setn(d->r->notes, "DIMS_ORIG_BYTES", "-");
    apr_table_setn(d->r->notes, "DIMS_DL_TIME", "-");
    apr_table_setn(d->r->notes, "DIMS_IM_TIME", "-");

    // Download image.
    apr_status_t status = dims_download_source_image(d, d->image_url);
    if (status != DIMS_SUCCESS) {
        return status;
    }

    // Execute Imagemagick commands.
    dims_processed_image *image = dims_process_image(d);
    if (image != NULL && image->error != DIMS_SUCCESS) {
        return image->error;
    } else if (image == NULL) {
        return DIMS_FAILURE;
    }

    // Serve the image.
    status = dims_send_image(d, image);
    if (status != DIMS_SUCCESS) {
        return status;
    }

    /* Record metrics for logging. */
    snprintf(buf, 128, "%d", d->status);
    apr_table_set(d->r->notes, "DIMS_STATUS", buf);

    snprintf(buf, 128, "%ld", d->source_image->used);
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

    return dims_status_to_http_code(d);
}

static dims_request_rec *
dims_create_request(request_rec *r)
{
    dims_request_rec *request = (dims_request_rec *) apr_palloc(r->pool, sizeof(dims_request_rec));
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(r->server->module_config, &dims_module);

    request->r = r;
    request->pool = r->pool;
    request->wand = NULL;
    request->config = config;
    request->client_config = NULL;
    request->no_image_url = request->config->no_image_url;
    request->use_no_image = 0;
    request->image_url = NULL;
    request->request_hash = NULL;
    request->status = DIMS_SUCCESS;
    request->start_time = apr_time_now();
    request->download_time = 0;
    request->imagemagick_time = 0;
    request->optimize_resize = config->optimize_resize;
    request->send_content_disposition = 0;
    request->content_disposition_filename = NULL;
    request->commands_list = apr_array_make(r->pool, 10, sizeof(dims_command_t));

    return request;
}

static char * 
dims_encode_spaces(apr_pool_t *pool, char *str)
{
    char *copy = apr_pstrdup(pool, str);

    char *s = copy;
    while (*s) {
        if (*s == ' ') {
            *s = '+';
        }

        s++;
    }

    return copy;
}

static apr_hash_t *
dims_parse_args(request_rec *r)
{
    apr_hash_t *query_params = apr_hash_make(r->pool);

    const size_t args_len = strlen(r->args) + 1;
    char *args = apr_pstrndup(r->pool, r->args, args_len);
    char *token;
    char *strtokstate;

    token = apr_strtok(args, "&", &strtokstate);
    while (token) {
        char *param = strtok(token, "=");
        apr_hash_set(query_params, param, APR_HASH_KEY_STRING, apr_pstrdup(r->pool, param + strlen(param) + 1));
        token = apr_strtok(NULL, "&", &strtokstate);
    }

    return query_params;
}

static apr_array_header_t *
dims_parse_commands(dims_request_rec *request, char *commands) {
    apr_array_header_t *commands_list = apr_array_make(request->pool, 10, sizeof(dims_command_t));

    const char *cmds = commands;
    while(cmds < commands + strlen(commands)) {
        char *command = ap_getword(request->pool, &cmds, '/'); 

        if(strlen(command) > 0) {
            char *args = ap_getword(request->pool, &cmds, '/');
            dims_command_t *cmd = (dims_command_t *) apr_palloc(request->pool, sizeof(dims_command_t)); 
            cmd->name = command;
            cmd->arg = dims_encode_spaces(request->pool, args);

            APR_ARRAY_PUSH(commands_list, dims_command_t) = *cmd;
        }
    }

    return commands_list;
}

static char *
dims_decrypt_eurl(request_rec *r, unsigned char *secret_key, char *eurl)
{
    // Hash secret via SHA-1.
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(secret_key, strlen((char *) secret_key), hash);

    // Convert to hex.
    char hex[SHA_DIGEST_LENGTH * 2 + 1];
    if (apr_escape_hex(hex, hash, SHA_DIGEST_LENGTH, 0, NULL) != APR_SUCCESS) {
        return NULL;
    }

    // Use first 16 bytes.
    unsigned char key[17];
    strncpy((char *) key, hex, 16);
    key[16] = '\0';

    // Force key to uppercase
    unsigned char *s = key;
    while (*s) { *s = toupper(*s); s++; }

    return aes_128_gcm_decrypt(r, key, eurl);
}

static apr_status_t
dims_request_parse(dims_request_rec *request, int dims4)
{
    request_rec *r = request->r;

    char *unparsed_commands = apr_pstrdup(r->pool, r->uri + 7);
    request->client_id = ap_getword(r->pool, (const char **) &unparsed_commands, '/');
    request->query_params = dims_parse_args(r);

    if (dims4) {
        request->signature = ap_getword(r->pool, (const char **) &unparsed_commands, '/');
        request->expiration = ap_getword(r->pool, (const char **) &unparsed_commands, '/');
    }

    request->commands = dims_encode_spaces(r->pool, unparsed_commands);
    request->commands_list = dims_parse_commands(request, request->commands);

    char *download = apr_hash_get(request->query_params, "download", APR_HASH_KEY_STRING);
    if (download != NULL && *download == '1') {
        request->send_content_disposition = 1;
    }

    // Determine the source image URL.
    char *url = apr_hash_get(request->query_params, "url", APR_HASH_KEY_STRING);
    char *eurl = apr_hash_get(request->query_params, "eurl", APR_HASH_KEY_STRING);
    if (eurl != NULL) {
        request->image_url = dims_decrypt_eurl(r, request->config->secret_key, eurl);

        if (request->image_url == NULL) {
            return DIMS_DECRYPTION_FAILURE;
        }
    } else if (url != NULL) {
        request->image_url = dims_encode_spaces(r->pool, url);
    } else {
        return DIMS_BAD_URL;
    }

    // Check for optimizeResize parameter.
    char *optimize_resize = apr_hash_get(request->query_params, "optimizeResize", APR_HASH_KEY_STRING);
    if (optimize_resize != NULL) {
        request->optimize_resize = atof(optimize_resize);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Overriding optimize resize: %f", request->optimize_resize);
    }

    request->request_hash = ap_md5(r->pool, 
        apr_pstrcat(r->pool, 
                    request->client_id, 
                    request->commands, 
                    request->image_url, 
                    NULL));

    // Calculate image filename for use with content disposition.
    apr_uri_t uri;
    if (apr_uri_parse(r->pool, request->image_url, &uri) == APR_SUCCESS) {
        if (!uri.path) {
            return DIMS_BAD_URL;
        }

        const char *path = apr_filepath_name_get(uri.path);
        request->content_disposition_filename = apr_pstrdup(r->pool, path);
    }

    return DIMS_SUCCESS;
}

apr_status_t
dims_handle_dims3(request_rec *r)
{
    dims_request_rec *d = dims_create_request(r);
    int status = dims_request_parse(d, 0);
    if (status != DIMS_SUCCESS) {
        return status;
    }

    if(!(d->client_config = apr_hash_get(d->config->clients, d->client_id, APR_HASH_KEY_STRING))) {
        return DIMS_BAD_CLIENT;
    }

    if(d->client_config && d->client_config->no_image_url) {
        d->no_image_url = d->client_config->no_image_url;
    }

    // Verify allowlist (dims3 only).
    if (verify_dims3_allowlist(d)) {
        return HTTP_UNAUTHORIZED;
    }

    return dims_handle_request(d);
}

apr_status_t
dims_handle_dims4(request_rec *r)
{
    dims_request_rec *d = dims_create_request(r);
    int status = dims_request_parse(d, 1);
    if (status != DIMS_SUCCESS) {
        return status;
    }

    if(!(d->client_config = apr_hash_get(d->config->clients, d->client_id, APR_HASH_KEY_STRING))) {
        return DIMS_BAD_CLIENT;
    }

    if(d->client_config && d->client_config->no_image_url) {
        d->no_image_url = d->client_config->no_image_url;
    }

    // Verify signature (dims4 only).
    if (verify_dims4_signature(d)) {
        return HTTP_UNAUTHORIZED;
    }

    return dims_handle_request(d);
}
