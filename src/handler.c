
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
    request->filename = NULL;
    request->cache_control = NULL;
    request->edge_control = NULL;
    request->etag = NULL;
    request->last_modified = NULL;
    request->request_hash = NULL;
    request->status = DIMS_SUCCESS;
    request->fetch_http_status = 0;
    request->start_time = apr_time_now();
    request->download_time = 0;
    request->imagemagick_time = 0;
    request->optimize_resize = config->optimize_resize;
    request->send_content_disposition = 0;
    request->content_disposition_filename = NULL;

    return request;
}

static apr_status_t
dims_request_parse(dims_request_rec *request)
{
    request_rec *r = request->r;

    char *unparsed_commands = apr_pstrdup(r->pool, r->uri + 7);
    request->unparsed_commands = unparsed_commands;

    request->client_id = ap_getword(request->pool, (const char **) &unparsed_commands, '/');
    request->signature = ap_getword(request->pool, (const char **) &unparsed_commands, '/');
    request->expiration = ap_getword(request->pool, (const char **) &unparsed_commands, '/');
    request->commands = apr_pstrdup(request->pool, unparsed_commands);
    char *s = request->commands;
    while (*s) {
        if (*s == ' ') {
            *s = '+';
        }

        s++;
    }

    /* Check first if URL is passed as a query parameter. */
    char *fixed_url = NULL, *eurl = NULL;
    if(r->args) {
        const size_t args_len = strlen(r->args) + 1;
        char *args = apr_pstrndup(request->r->pool, request->r->args, args_len);
        char *token;
        char *strtokstate;
        token = apr_strtok(args, "&", &strtokstate);
        while (token) {
            if(strncmp(token, "url=", 4) == 0) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request->r, "ARG: %s", token);
                fixed_url = apr_pstrdup(r->pool, token + 4);
                ap_unescape_url(fixed_url);

                if (strcmp(fixed_url, "") == 0) {
                    return DIMS_BAD_URL;
                }
            } else if (strncmp(token, "download=1", 10) == 0) {
                request->send_content_disposition = 1;

            } else if (strncmp(token, "eurl=", 4) == 0) {
                eurl = apr_pstrdup(r->pool, token + 5);

                // Hash secret via SHA-1.
                unsigned char *secret = (unsigned char *) request->client_config->secret_key;
                unsigned char hash[SHA_DIGEST_LENGTH];
                SHA1(secret, strlen((char *) secret), hash);

                // Convert to hex.
                char hex[SHA_DIGEST_LENGTH * 2 + 1];
                if (apr_escape_hex(hex, hash, SHA_DIGEST_LENGTH, 0, NULL) != APR_SUCCESS) {
                    return DIMS_DECRYPTION_FAILURE;
                }

                // Use first 16 bytes.
                unsigned char key[17];
                strncpy((char *) key, hex, 16);
                key[16] = '\0';

                // Force key to uppercase
                unsigned char *s = key;
                while (*s) { *s = toupper(*s); s++; }

                if (request->config->encryption_algorithm != NULL &&
                    strncmp((char *)request->config->encryption_algorithm, "AES/GCM/NoPadding", strlen("AES/GCM/NoPadding")) == 0) {

                    fixed_url = aes_128_gcm_decrypt(r, key, eurl);
                } else {
                    //Default is AES/ECB/PKCS5Padding
                    unsigned char *encrypted_text = apr_palloc(r->pool, apr_base64_decode_len(eurl));
                    int encrypted_length = apr_base64_decode((char *) encrypted_text, eurl);
                    fixed_url = aes_128_decrypt(r, key, encrypted_text, encrypted_length);
                }

                if (fixed_url == NULL) {
                    return DIMS_DECRYPTION_FAILURE;
                }

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request->r, "Decrypted URL: %s", fixed_url);

                break;

            } else if (strncmp(token, "optimizeResize=", 4) == 0) {
                request->optimize_resize = atof(token + 15);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request->r, "Overriding optimize resize: %f", request->optimize_resize);
            }
            token = apr_strtok(NULL, "&", &strtokstate);
        }
    }

    // Convert '+' in the fixed_url to ' '.
    char *image_url = apr_pstrdup(request->r->pool, fixed_url);
    s = image_url;
    while (*s) {
        if (*s == '+') {
            *s = ' ';
        }

        s++;
    }

    request->image_url = image_url;
    request->request_hash = ap_md5(request->pool, 
        apr_pstrcat(request->pool, request->client_id, request->commands, request->image_url, NULL));

    /* Calculate image filename for use with content disposition. */
    apr_uri_t uri;
    if (apr_uri_parse(r->pool, request->image_url, &uri) == APR_SUCCESS) {
        if (!uri.path) {
            return DIMS_BAD_URL;
        }

        const char *path = apr_filepath_name_get(uri.path);
        request->content_disposition_filename = apr_pstrdup(request->r->pool, path);
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
