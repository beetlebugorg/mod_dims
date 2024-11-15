#ifndef _REQUEST_H
#define _REQUEST_H

#include <httpd.h>
#include <MagickWand/MagickWand.h>

#include "configuration.h"

typedef struct dims_image_data_t {
    char *data;
    size_t size;
    size_t used;
    long response_code;

    // Cache control headers
    char *cache_control;
    char *edge_control;
    char *last_modified;
    char *etag;
    int max_age;
} dims_image_data_t;

typedef struct dims_command_t {
    char *name;
    char *arg;
} dims_command_t;

typedef struct dims_request_rec {
    request_rec *r;

    apr_pool_t *pool;

    MagickWand *wand;

    /* Client ID of this request. */
    char *client_id;
    char *request_hash;

    /* The URL to the image being manipulated. */
    char *image_url;
    int use_no_image;

    /* The URL to the NOIMAGE image in case of failures. */
    char *no_image_url;

    /* The parsed commands with the signature and expiration timestamp removed. */
    char *commands;
    apr_hash_t *query_params;
    apr_array_header_t *commands_list;

    /* The source image. */
    dims_image_data_t *source_image;

    /* The global configuration. */
    dims_config_rec *config;

    /* The client specific configuration, if available. */
    dims_client_config_rec *client_config;

    /* The current status of this request.  If downloading
     * or manipulating the image times out this will
     * be set to DIMS_*_TIMEOUT.  If everything is ok it will
     * be set to DIMS_SUCCESS.
     */
    apr_status_t status;

    /* Time this request started.  Used for statistics. */
    apr_time_t start_time;
    apr_time_t download_time;
    apr_time_t imagemagick_time;
    
    /* Use a whitelist, or use a secret key passed on the URI */
    char *signature;
    char *expiration;

    /* Should Content-Disposition header bet set. */
    int send_content_disposition;
    char *content_disposition_filename;
} dims_request_rec;

#endif