
#include <httpd.h>
#include <scoreboard.h>
#include <apr.h>
#include <openssl/sha.h>

#include "mod_dims.h"
#include "handler.h"
#include "configuration.h"
#include "request.h"
#include "module.h"
#include "encryption.h"

static void show_time(request_rec *r, apr_interval_time_t tsecs)
{
    int days, hrs, mins, secs;

    secs = (int)(tsecs % 60);
    tsecs /= 60;
    mins = (int)(tsecs % 60);
    tsecs /= 60;
    hrs = (int)(tsecs % 24);
    days = (int)(tsecs / 24);

    ap_rprintf(r, "Uptime: ");

    if (days) ap_rprintf(r, " %d day%s", days, days == 1 ? "" : "s");
    if (hrs) ap_rprintf(r, " %d hour%s", hrs, hrs == 1 ? "" : "s");
    if (mins) ap_rprintf(r, " %d minute%s", mins, mins == 1 ? "" : "s");
    if (secs) ap_rprintf(r, " %d second%s", secs, secs == 1 ? "" : "s");

    ap_rprintf(r, "\n");
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
    dims_request_rec *d = (dims_request_rec *) 
            apr_palloc(r->pool, sizeof(dims_request_rec));

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
        char *fixed_url, *url;

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

        /* HACK: If URL has "http:/" instead of "http://", correct it. */
        url = strstr(r->uri, "http:/");
        if(url && *(url + 6) != '/') {
            fixed_url = apr_psprintf(r->pool, "http://%s", url + 6);
        } else if(!url) {
            return dims_cleanup(d, NULL, DIMS_BAD_URL);
        } else {
            fixed_url = url;
        }

        char *commands = apr_psprintf(r->pool, "%s", appid);

        if(bitmap & LEGACY_DIMS_RESIZE && bitmap & LEGACY_DIMS_CROP) {
            if(!width && !height) {
                return dims_cleanup(d, NULL, DIMS_BAD_ARGUMENTS);
            }
            commands = apr_psprintf(r->pool, "%s/legacy_thumbnail/%ldx%ld", 
                    commands, (long) width, (long) height);
        } else if(bitmap & LEGACY_DIMS_CROP || bitmap & LEGACY_DIMS_RESIZE) {
            char *cmd = (bitmap & LEGACY_DIMS_RESIZE) ? "resize" : "legacy_crop";

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
        char *p, *url = NULL, *fixed_url = NULL, *commands = NULL, *eurl = NULL;
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

                        fixed_url = aes_128_gcm_decrypt(r, key, eurl);
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

        /* Parse out URL to image.
         * HACK: If URL has "http:/" instead of "http://", correct it. 
         */
        commands = apr_pstrdup(r->pool, r->uri);
        if(fixed_url == NULL) {
            url = strstr(r->uri, "http:/");
            if(url && *(url + 6) != '/') {
                fixed_url = apr_psprintf(r->pool, "http://%s", url + 6);
            } else if(!url) {
                return dims_cleanup(d, NULL, DIMS_BAD_URL);
            } else {
                fixed_url = url;
            }

            /* Strip URL off URI.  This leaves only the tranformation parameters. */
            p = strstr(commands, "http:/");
            if(!p) return dims_cleanup(d, NULL, DIMS_BAD_URL);
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
        apr_time_t uptime;

        ap_set_content_type(r, "text/plain");
        ap_rvputs(r, "ALIVE\n\n", NULL);

        uptime = (apr_uint32_t) apr_time_sec(apr_time_now() -
                ap_scoreboard_image->global->restart_time);

        show_time(r, uptime);

        ap_rprintf(r, "Restart time: %s\n", 
                ap_ht_time(r->pool,
                ap_scoreboard_image->global->restart_time,
                "%A, %d-%b-%Y %H:%M:%S %Z", 0));

        ap_rprintf(r, "\nmod_dims version: %s (%s)\n", MODULE_VERSION, MODULE_RELEASE);
        ap_rprintf(r, "ImageMagick version: %s\n", GetMagickVersion(NULL));
        ap_rprintf(r, "libcurl version: %s\n", curl_version());

        ap_rprintf(r, "\nDetails\n-------\n");
        
        ap_rprintf(r, "Successful requests: %d\n", 
                apr_atomic_read32(&stats->success_count));
        ap_rprintf(r, "Failed requests: %d\n\n", 
                apr_atomic_read32(&stats->failure_count));
        ap_rprintf(r, "Download timeouts: %d\n", 
                apr_atomic_read32(&stats->download_timeout_count));
        ap_rprintf(r, "Imagemagick Timeouts: %d\n", 
                apr_atomic_read32(&stats->imagemagick_timeout_count));

        ap_rflush(r);
        return OK;
    }

    return DECLINED;
}
