
#include <httpd.h>
#include <util_md5.h>
#include <scoreboard.h>
#include <apr.h>
#include <apr_hash.h>
#include <openssl/sha.h>

#include "mod_dims.h"
#include "handler.h"
#include "configuration.h"
#include "request.h"
#include "module.h"
#include "encryption.h"
#include "status.h"

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
dims_request_parse(dims_request_rec *request)
{
    request_rec *r = request->r;

    char *unparsed_commands = apr_pstrdup(r->pool, r->uri + 7);
    request->unparsed_commands = unparsed_commands;

    request->client_id = ap_getword(r->pool, (const char **) &unparsed_commands, '/');
    request->signature = ap_getword(r->pool, (const char **) &unparsed_commands, '/');
    request->expiration = ap_getword(r->pool, (const char **) &unparsed_commands, '/');
    request->commands = dims_encode_spaces(r->pool, unparsed_commands);
    request->query_params = dims_parse_args(r);

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
apr_status_t 
dims_handler(request_rec *r) 
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Handler %s : %s", r->handler, r->uri);

    if(strcmp(r->handler, "dims-status") == 0) {
        return status_handler(r);
    }

    if (!(strcmp(r->handler, "dims3") == 0 || strcmp(r->handler, "dims4") == 0)) {
        return DECLINED;
    }

    dims_request_rec *d = dims_create_request(r);
    int status = dims_request_parse(d);
    if (status != DIMS_SUCCESS) {
        return status;
    }

    /* Set initial notes to be logged by mod_log_config. */
    apr_table_setn(r->notes, "DIMS_STATUS", "0");
    apr_table_setn(r->notes, "DIMS_ORIG_BYTES", "-");
    apr_table_setn(r->notes, "DIMS_DL_TIME", "-");
    apr_table_setn(r->notes, "DIMS_IM_TIME", "-");

    if(!(d->client_config = apr_hash_get(d->config->clients, d->client_id, APR_HASH_KEY_STRING))) {
        return DIMS_BAD_CLIENT;
    }

    if(d->client_config && d->client_config->no_image_url) {
        d->no_image_url = d->client_config->no_image_url;
    }

    if ((strcmp(r->handler, "dims3") == 0)) {
        return dims_handle_dims3(d);
    } else if (strcmp(r->handler, "dims4") == 0) {
        return dims_handle_dims4(d);
    }

    return DECLINED;
}
