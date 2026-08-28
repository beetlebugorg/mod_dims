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
#include "dims5.h"
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

    if (d->scheme == DIMS_SCHEME_DIMS5) {
        apr_status_t verified = dims5_verify(d);

        if (verified != DIMS_SUCCESS) {
            return dims_cleanup(d, NULL, verified);
        }

        goto verified;
    }

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
            char *strtokstate = NULL;

            token = apr_strtok(args, "&", &strtokstate);
            while (token) {
                /* A parameter with no equals sign has no value. */
                char *equals = strchr(token, '=');

                if (equals != NULL) {
                    *equals = '\0';
                    apr_hash_set(params, token, APR_HASH_KEY_STRING,
                            apr_pstrdup(d->r->pool, equals + 1));
                }

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

        /* Check the key before building the input. apr_pstrcat stops at its
         * first NULL argument, which would hash the expiry alone. */
        if (d->client_config->secret_key == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
                "Developer key not set for client '%s'", d->client_config->id);
            return dims_cleanup(d, "Missing Developer Key", DIMS_BAD_CLIENT);
        }

        // Standard signature params.
        char *signature_params = apr_pstrcat(d->pool, expires_str, d->client_config->secret_key, commands, d->image_url, NULL);

        /* Concatenate the additional params _keys names. _keys is optional. */
        char *keys = apr_hash_get(params, "_keys", APR_HASH_KEY_STRING);

        if (keys != NULL) {
            char *strtokstate = NULL;
            char *token = apr_strtok(keys, ",", &strtokstate);

            while (token) {
                const char *value = apr_hash_get(params, token, APR_HASH_KEY_STRING);

                signature_params = apr_pstrcat(d->pool, signature_params, value, NULL);
                token = apr_strtok(NULL, ",", &strtokstate);
            }
        }

        // Hash.
        gen_hash = ap_md5(d->pool, (unsigned char *) signature_params);

        if (strncasecmp(hash, gen_hash, 6) != 0) {
            gen_hash[7] = '\0';
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG,0, d->r,
                "Key Mismatch: wanted %6s got %6s [%s?url=%s]", gen_hash, hash, d->r->uri, d->image_url);
            return dims_cleanup(d, "Key mismatch", DIMS_BAD_URL);
        }
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
            "secret key (%s) to validated (%s:%s)", hash,  d->unparsed_commands,d->image_url);
    }

verified:
    d->request_hash = ap_md5(d->pool,
            (unsigned char *) apr_pstrcat(d->pool,
                d->client_id ? d->client_id : "",
                d->unparsed_commands, d->image_url, NULL));

    dims_parse_commands(d);
    dims_set_optimal_geometry(d);

    if (d->image_url && *d->image_url == '/') {
        request_rec *sub_req = ap_sub_req_lookup_uri(d->image_url, d->r, NULL);

        if (d->config->default_image_prefix != NULL) {
            d->image_url = apr_pstrcat(d->r->pool, d->config->default_image_prefix, d->image_url, NULL);
        } else if (sub_req && sub_req->canonical_filename) {
            /* The subrequest ran httpd's access control. A caller must not read
             * a local file the server protects, so honor a denial here. Only an
             * access-control status is refused; a missing file and every other
             * result stay on the path below. */
            if (sub_req->status == HTTP_FORBIDDEN ||
                    sub_req->status == HTTP_UNAUTHORIZED) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                        "Access to local image %s is not allowed: %d",
                        d->image_url, sub_req->status);
                dims_free_request(d);
                return sub_req->status;
            }
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

        /* apr_uri_parse leaves path NULL for a URL with no path component,
         * such as http://example.com. */
        char *filename;

        if (!uri.path || !uri.hostname) {
            return dims_cleanup(d, "Invalid URL in request.", DIMS_BAD_URL);
        }

        filename = strrchr(uri.path, '/');
        if (!filename) {
            return dims_cleanup(d, "Invalid URL in request.", DIMS_BAD_URL);
        }

        if (*filename == '/') {
            d->filename = ++filename;
        }

        hostname = uri.hostname;

        /* A signed request consults the allowlist only under
         * DimsAllowlistSigned enforce. */
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
             * The source failed. Send the error image, and report the status
             * the failure produced. dims_fetch_remote_image records one only
             * for a 404, so anything else needs DIMS_FAILURE rather than
             * DIMS_IGNORE, which would keep the success it was marked with.
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

    if(!d->image_url ) {
        return DECLINED;
    }

    d->wand = NewMagickWand();

    if(apr_uri_parse(d->pool, d->image_url, &uri) != APR_SUCCESS) {
        return dims_cleanup(d, "Invalid URL in request.", DIMS_BAD_URL);
    }

    /* The sizer has no signature, so the allowlist is its only gate and
     * applies whatever DimsAllowlistSigned holds. */
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
    d->wand = NULL;
    ap_set_content_type(d->r, "text/plain");
    ap_rprintf(d->r, "{\n\t\"height\": %ld,\n\t\"width\": %ld\n}", height, width );
    return OK;

}



/*
 * The httpd handler, called for /dims/, /dims3/, /dims4/, and a local image.
 *
 * It reads the request into a dims_request_rec and hands it to
 * dims_handle_request, dims_sizer, or dims_process_image.
 */
apr_status_t
dims_handler(request_rec *r)
{
    /* apr_pcalloc, so a field the list below does not name is zero rather
     * than whatever the pool held. */
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
    } else if ((strcmp(r->handler, "dims3") == 0) ||
            (r->uri && strncmp(r->uri, "/dims3/", 7) == 0) ||
            (strcmp(r->handler, "dims4") == 0 )) {
        /* Handle new-style DIMS parameters. */
        char *p, *fixed_url = NULL, *commands = NULL, *eurl = NULL;
        if (( strcmp( r->handler,"dims4") == 0)) {
               d->use_secret_key = 1;
        }

        /* The commands start at a fixed offset, so the location has to be
         * the one that offset belongs to. */
        char *unparsed_commands;

        if (!dims_endpoint_prefix(r->uri)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "The dims3 and dims4 handlers need a location of /dims3/ "
                    "or /dims4/. This request arrived at %s.",
                    r->uri ? r->uri : "");
            return dims_cleanup(d, "Invalid URL in request.", DIMS_BAD_URL);
        }

        unparsed_commands = apr_pstrdup(r->pool, r->uri + DIMS_ENDPOINT_PREFIX_LEN);
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
                /* dims_param_value compares the whole name, so a token
                 * shorter than the name never matches. */
                const char *value;

                if((value = dims_param_value(token, "url=")) != NULL) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "ARG: %s", token);
                    fixed_url = apr_pstrdup(r->pool, value);
                    ap_unescape_url(fixed_url);

                    if (strcmp(fixed_url, "") == 0) {
                        return dims_cleanup(d, NULL, DIMS_BAD_URL);
                    }
                } else if (strcmp(token, "download=1") == 0) {
                    d->send_content_disposition = 1;

                } else if ((value = dims_param_value(token, "eurl=")) != NULL) {
                    eurl = apr_pstrdup(r->pool, value);

                    // Hash secret via SHA-1.
                    unsigned char *secret = (unsigned char *) d->client_config->secret_key;
                    unsigned char hash[SHA_DIGEST_LENGTH];

                    /* DimsAddClient stores a secret of "-" as NULL, and
                     * there is nothing to derive a key from. */
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

                } else if ((value = dims_param_value(token, "optimizeResize=")) != NULL) {
                    d->optimize_resize = atof(value);
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Overriding optimize resize: %f", d->optimize_resize);
                }
                token = apr_strtok(NULL, "&", &strtokstate);
            }
        }

        /* The URL sits in the path when no query parameter had it. */
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
        /* One less than the prefix keeps the leading slash, which
         * dims_handle_request steps over. */
        d->unparsed_commands = commands + DIMS_ENDPOINT_PREFIX_LEN - 1;

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
    } else if(strcmp(r->handler, "dims5") == 0) {
        d->scheme = DIMS_SCHEME_DIMS5;

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
