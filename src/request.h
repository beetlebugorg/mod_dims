#ifndef _REQUEST_H
#define _REQUEST_H

#include <httpd.h>
#include <MagickWand/MagickWand.h>

#include "configuration.h"

typedef struct dims_request_rec dims_request_rec;

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

    /* The parsed commands with the signature and expiration timestamp removed. */
    char *commands;

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
    char *signature;
    char *expiration;

    /* Should Content-Disposition header bet set. */
    int send_content_disposition;
    char *content_disposition_filename;
};

#endif