/*
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

#ifndef _MOD_DIMS_H
#define _MOD_DIMS_H

#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_file_info.h>
#include <apr_atomic.h>
#include <apr_queue.h>
#include <apr_base64.h>
#include <apr_escape.h>
#include <apr_lib.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_request.h>
#include <http_log.h>
#include <http_protocol.h>

#include <wand/magick-wand.h>

#include <curl/curl.h>

#define LEGACY_DIMS_RESIZE 1
#define LEGACY_DIMS_REFORMAT 2
#define LEGACY_DIMS_CROP 4
#define LEGACY_DIMS_SHARPEN 8
#define LEGACY_DIMS_JPG 256
#define LEGACY_DIMS_GIF 512
#define LEGACY_DIMS_PNG 1024

#define DIMS_IGNORE -1
#define DIMS_SUCCESS 0
#define DIMS_FAILURE 1
#define DIMS_DOWNLOAD_TIMEOUT 2
#define DIMS_IMAGEMAGICK_TIMEOUT 4
#define DIMS_BAD_CLIENT 8
#define DIMS_BAD_URL 16
#define DIMS_BAD_ARGUMENTS 32
#define DIMS_HOSTNAME_NOT_IN_WHITELIST 64
#define DIMS_FILE_NOT_FOUND 128

typedef struct dims_request_rec dims_request_rec;
typedef struct dims_config_rec dims_config_rec;
typedef struct dims_client_config_rec dims_client_config_rec;
typedef struct {
    char *data;
    size_t size;
    size_t used;
    long response_code;
} dims_image_data_t;

typedef apr_status_t(dims_operation_func) (dims_request_rec *, char *args, char **err);
void smartCrop(MagickWand *wand, int resolution, unsigned long cropWidth, unsigned long cropHeight);
CURLcode dims_get_image_data(dims_request_rec *d, char *fetch_url, dims_image_data_t *data);

dims_operation_func 
    dims_strip_operation,
    dims_resize_operation,
    dims_crop_operation,
    dims_thumbnail_operation,
    dims_sharpen_operation,
    dims_quality_operation,
    dims_format_operation,
    dims_legacy_thumbnail_operation,
    dims_smart_crop_operation,
    dims_brightness_operation,
    dims_flipflop_operation,
    dims_sepia_operation,
    dims_grayscale_operation,
    dims_autolevel_operation,
    dims_rotate_operation,
    dims_invert_operation,
    dims_watermark_operation,
    dims_legacy_crop_operation;

struct dims_config_rec {
    int download_timeout;
    int imagemagick_timeout;

    apr_table_t *whitelist;
    apr_hash_t *clients;
    apr_table_t *ignore_default_output_format;

    char *no_image_url;
    long no_image_expire;
    long default_expire;
    int strip_metadata;
    float optimize_resize;
    int include_disposition;
    int disable_encoded_fetch;
    char *default_output_format;

    MagickSizeType area_size;
    MagickSizeType memory_size;
    MagickSizeType map_size;
    MagickSizeType disk_size;

    int curl_queue_size;
    char *secret_key;
    long max_expiry_period;
    char *cache_dir;
    char *default_image_prefix;
};

struct dims_client_config_rec {
    char *id;
    char *no_image_url;
    int cache_control_max_age;
    int edge_control_downstream_ttl;
    int trust_src;
    int min_src_cache_control;
    int max_src_cache_control;
    char *secret_key;
};

struct dims_request_rec {
    request_rec *r;

    apr_pool_t *pool;

    MagickWand *wand;

    /* Client ID of this request. */
    char *client_id;

    /* The URL to the image being manipulated. */
    char *image_url;
    int use_no_image;

    /* The URL to the NOIMAGE image in case of failures. */
    char *no_image_url;

    /* The filename if this is a local request. */
    char *filename;

    /* The unparsed commands (resize, crop, etc). */
    char *unparsed_commands;

    /* The original image size in bytes. */
    long original_image_size;

    /* The sample factor for optimizing resizing. */
    float optimize_resize;

    /* The global configuration. */
    dims_config_rec *config;

    /* The client specific configuration, if available. */
    dims_client_config_rec *client_config;

    /* The cache headers from the downloaded image. */
    char *cache_control;
    char *edge_control;
    char *last_modified;
    char *etag;
    char *request_hash;

    /* The current status of this request.  If downloading
     * or manipulating the image times out this will
     * be set to DIMS_*_TIMEOUT.  If everything is ok it will
     * be set to DIMS_SUCCESS.
     */
    apr_status_t status;

    /* The HTTP status code from fetching the original image */
    apr_status_t fetch_http_status;

    /* Time this request started.  Used for statistics. */
    apr_time_t start_time;
    apr_time_t download_time;
    apr_time_t imagemagick_time;
    
    /* Use a whitelist, or use a secret key passed on the URI */
    int use_secret_key;

    /* Should Content-Disposition header bet set. */
    int send_content_disposition;
    char *content_disposition_filename;
};

#endif
