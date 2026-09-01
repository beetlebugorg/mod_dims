/*
 * The /dims5/ endpoint.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "dims5.h"
#include "metrics.h"
#include "encryption.h"
#include "signature.h"
#include "url.h"

#include <string.h>

/* Reads one query parameter out of the request, decoded. */
static char *
query_value(dims_request_rec *d, const char *name)
{
    char *args;
    char *token;
    char *state = NULL;
    char *found = NULL;
    char *prefix;

    if (d->r->args == NULL) {
        return NULL;
    }

    args = apr_pstrdup(d->pool, d->r->args);
    prefix = apr_pstrcat(d->pool, name, "=", NULL);

    for (token = apr_strtok(args, "&", &state); token != NULL;
            token = apr_strtok(NULL, "&", &state)) {
        const char *value = dims_param_value(token, prefix);

        if (value != NULL) {
            found = apr_pstrdup(d->pool, value);
            ap_unescape_url(found);
        }
    }

    return found;
}

apr_status_t
dims5_verify(dims_request_rec *d)
{
    const char *key = d->config->signing_key;
    char *commands;
    char *signature;
    char *expected;
    char *image_url;
    char *eurl;

    if (key == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                "DimsSigningKey is not set, so no /dims5/ request can be "
                "checked, on request: %s", d->r->uri);
        return DIMS_BAD_CLIENT;
    }

    if (d->r->uri == NULL || strlen(d->r->uri) < DIMS5_PREFIX_LEN) {
        return DIMS_BAD_URL;
    }

    /* Everything after the prefix, up to the query string. */
    commands = apr_pstrdup(d->pool, d->r->uri + DIMS5_PREFIX_LEN);

    signature = query_value(d, "sig");
    if (signature == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
                "No signature, on request: %s", d->r->uri);
        return DIMS_BAD_URL;
    }

    eurl = query_value(d, "eurl");
    if (eurl != NULL) {
        unsigned char derived[DIMS_AES_KEY_BYTES];
        char *decrypted;
        char *at;

        if (!dims_derive_key(key, derived)) {
            return DIMS_BAD_CLIENT;
        }

        /* A plus in the base64 arrives as a space. */
        for (at = eurl; *at != '\0'; at++) {
            if (*at == ' ') {
                *at = '+';
            }
        }

        decrypted = aes_128_gcm_decrypt(d->r, derived, (unsigned char *) eurl);
        if (decrypted == NULL) {
            dims_metrics_eurl(0);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
                    "Cannot decrypt eurl, on request: %s", d->r->uri);
            return DIMS_BAD_URL;
        }

        dims_metrics_eurl(1);
        image_url = decrypted;
    } else {
        image_url = query_value(d, "url");
    }

    if (image_url == NULL || *image_url == '\0') {
        return DIMS_BAD_URL;
    }

    /*
     * The message puts one field per line, so a field holding a line break
     * could stand in for two.
     */
    if (!dims_signature_field_ok(commands) ||
            !dims_signature_field_ok(image_url)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
                "A control character is not allowed in a signed field, on "
                "request: %s", d->r->uri);
        return DIMS_BAD_URL;
    }

    expected = dims_signature_compute(d->pool, key,
            dims_signature_message(d->pool, commands, image_url,
                    dims_signed_query(d->pool, d->r->args)));

    if (expected == NULL || !dims_signature_equal(expected, signature)) {
        dims_metrics_signature(DIMS_ENDPOINT_DIMS5, DIMS_SIG_MISMATCH);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r,
                "Signature mismatch, on request: %s", d->r->uri);
        return DIMS_BAD_URL;
    }

    dims_metrics_signature(DIMS_ENDPOINT_DIMS5, DIMS_SIG_OK);

    d->image_url = image_url;
    d->unparsed_commands = commands;
    d->client_id = NULL;
    d->client_config = apr_pcalloc(d->pool, sizeof(dims_client_config_rec));
    d->no_image_url = d->config->no_image_url;

    if (query_value(d, "download") != NULL) {
        apr_uri_t uri;

        d->send_content_disposition = 1;

        if (apr_uri_parse(d->pool, image_url, &uri) == APR_SUCCESS &&
                uri.path != NULL) {
            d->content_disposition_filename =
                    apr_pstrdup(d->pool, apr_filepath_name_get(uri.path));
        }
    }

    return DIMS_SUCCESS;
}
