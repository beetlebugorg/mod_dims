/*
 * The request handlers.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "handler.h"
#include "configuration.h"
#include "curl.h"
#include "netguard.h"
#include "url.h"
#include "encryption.h"
#include "status.h"
#include "pipeline.h"

#include <util_md5.h>
#include <openssl/sha.h>
#include <strings.h>


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
            const char *req_port;
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

        char *hostname;
        apr_uri_t uri;
        int found = 0;

        /* The hostname must be on the allowlist. dims_host_allowed makes the
         * match; the redirect check and the sizer make the same one. */
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

        /*
         * A signed request has never consulted the allowlist. Refusing one now
         * would change which URLs /dims4/ accepts, so it waits for the
         * operator to set DimsAllowlistSigned to enforce.
         */
        if ( d->use_secret_key == 1 && !d->config->allowlist_signed ) {
            found = 1;
        } else {
            found = dims_host_allowed(d->config->whitelist, hostname);
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
        if (fetch_url && dims_fetch_remote_image(d, fetch_url) != 0) {
            /*
             * The source failed. Send the error image instead, and when there
             * is none, report what went wrong.
             *
             * This returned DECLINED, which leaked the wand and handed the
             * request back to httpd. httpd looked for a file at the request
             * path, did not find one, and answered 404. The status was right
             * by accident and said nothing about what happened.
             */
            /*
             * Report the status the source failure produced, and a plain
             * failure when it produced none.
             *
             * DIMS_IGNORE alone is not enough. dims_fetch_remote_image only
             * sets a status when the origin answered 404; for any other
             * failure the request is still marked successful, and asking
             * dims_cleanup to keep that status answers 200 with no body.
             */
            if (dims_fetch_remote_image(d, NULL) != 0) {
                return dims_cleanup(d, NULL,
                        d->status != DIMS_SUCCESS ? DIMS_IGNORE : DIMS_FAILURE);
            }
        }

        return dims_process_image(d);
    }

    return dims_cleanup(d, NULL, DIMS_FAILURE);
}

/**
 * dims_sizer - return the size of the image (height: X\n width: X)
 */
apr_status_t
dims_sizer(dims_request_rec *d)
{
    
    apr_uri_t uri;
    long width, height;

    d->wand = NewMagickWand();
    if(!d->image_url ) {
        return DECLINED;
    }
    if(apr_uri_parse(d->pool, d->image_url, &uri) != APR_SUCCESS) {
        return dims_cleanup(d, "Invalid URL in request.", DIMS_BAD_URL);
    }

    /*
     * The sizer took any URL from any caller and reported whether it decoded
     * as an image, which made it a scanner. It carries no signature, so the
     * allowlist is the only gate it can have, and it applies here whatever
     * DimsAllowlistSigned holds.
     */
    if(!dims_host_allowed(d->config->whitelist, uri.hostname)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                "Requested URL has hostname that is not in the "
                "whitelist. (%s)", uri.hostname ? uri.hostname : "");
        return dims_cleanup(d, NULL, DIMS_HOSTNAME_NOT_IN_WHITELIST);
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
    /*
     * apr_pcalloc, not apr_palloc. The list below sets one field at a time,
     * so every field it does not name holds whatever the pool handed over.
     * Zeroing first makes a forgotten field NULL or zero rather than garbage.
     */
    dims_request_rec *d = (dims_request_rec *)
            apr_pcalloc(r->pool, sizeof(dims_request_rec));

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
    d->net_apply_allowlist = DIMS_ALLOWLIST_SKIP;
    d->net_refusal = DIMS_NET_OK;

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
        char *fixed_url;

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

        fixed_url = dims_path_image_url(r->pool, r->uri, NULL);
        if(!fixed_url) {
            return dims_cleanup(d, NULL, DIMS_BAD_URL);
        }

        char *commands = apr_psprintf(r->pool, "%s", appid);

        if(bitmap & LEGACY_DIMS_RESIZE && bitmap & LEGACY_DIMS_CROP) {
            if(!width && !height) {
                return dims_cleanup(d, NULL, DIMS_BAD_ARGUMENTS);
            }
            commands = apr_psprintf(r->pool, "%s/legacy_thumbnail/%ldx%ld", 
                    commands, (long) width, (long) height);
        } else if(bitmap & LEGACY_DIMS_CROP || bitmap & LEGACY_DIMS_RESIZE) {
            const char *cmd = (bitmap & LEGACY_DIMS_RESIZE) ? "resize" : "legacy_crop";

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
        char *p, *fixed_url = NULL, *commands = NULL, *eurl = NULL;
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

                    // Hash secret via SHA-1.
                    unsigned char *secret = (unsigned char *) d->client_config->secret_key;
                    unsigned char hash[SHA_DIGEST_LENGTH];

                    /*
                     * DimsAddClient stores a secret of "-" as NULL, so a
                     * client configured without one reaches this with nothing
                     * to hash. strlen then read from address zero and killed
                     * the worker, on a query parameter that needs no
                     * signature.
                     */
                    if (secret == NULL) {
                        return dims_cleanup(d, "Missing Developer Key",
                                DIMS_BAD_CLIENT);
                    }

                    SHA1(secret, strlen((char *) secret), hash);

                    // Convert to hex.
                    char hex[SHA_DIGEST_LENGTH * 2 + 1];
                    if (apr_escape_hex(hex, hash, SHA_DIGEST_LENGTH, 0, NULL) != APR_SUCCESS) {
                        return dims_cleanup(d, "URL Decryption Failed", DIMS_FAILURE);
                    }

                    // Use first 16 bytes.
                    unsigned char key[17];
                    strncpy((char *) key, hex, 16);
                    key[16] = '\0';

                    // Force key to uppercase
                    unsigned char *s = key;
                    while (*s) { *s = toupper(*s); s++; }

                    if (d->config->encryption_algorithm != NULL &&
                        strncmp((char *)d->config->encryption_algorithm, "AES/GCM/NoPadding", strlen("AES/GCM/NoPadding")) == 0) {

                        fixed_url = aes_128_gcm_decrypt(r, key, (unsigned char *) eurl);
                    } else {
                        //Default is AES/ECB/PKCS5Padding
                        unsigned char *encrypted_text = apr_palloc(r->pool, apr_base64_decode_len(eurl));
                        int encrypted_length = apr_base64_decode((char *) encrypted_text, eurl);
                        fixed_url = aes_128_decrypt(r, key, encrypted_text, encrypted_length);
                    }
                    if (fixed_url == NULL) {
                        return dims_cleanup(d, "URL Decryption Failed", DIMS_FAILURE);
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

        /* The URL sits in the path when no query parameter carried it. */
        commands = apr_pstrdup(r->pool, r->uri);
        if(fixed_url == NULL) {
            fixed_url = dims_path_image_url(r->pool, r->uri, NULL);
            if(!fixed_url) {
                return dims_cleanup(d, NULL, DIMS_BAD_URL);
            }

            /* Strip the URL off the copy, which leaves only the commands. */
            if(!dims_path_image_url(r->pool, commands, &p)) {
                return dims_cleanup(d, NULL, DIMS_BAD_URL);
            }
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
        return dims_status_handler(r);
    } else if(strcmp(r->handler, "dims-sizer") == 0) {
        char *fixed_url = dims_path_image_url(r->pool, r->uri, NULL);
        if(!fixed_url) {
            return dims_cleanup(d, NULL, DIMS_BAD_URL);
        }
        d->image_url = fixed_url;
        d->unparsed_commands = NULL;


        return dims_sizer(d);
    }

    return DECLINED;
}
