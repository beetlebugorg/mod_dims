/*
 * Turning a request status into an HTTP status.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mod_dims.h"

int
dims_http_status(int status)
{
    switch (status) {
        case DIMS_SUCCESS:
            return HTTP_OK;

        /* The caller asked for something the service cannot parse. */
        case DIMS_BAD_URL:
        case DIMS_BAD_ARGUMENTS:
            return HTTP_BAD_REQUEST;

        /* The guard refused the target. go-dims answers 400 for the same
         * refusal, so the two projects agree on what a caller sees. */
        case DIMS_NETWORK_REFUSED:
            return HTTP_BAD_REQUEST;

        case DIMS_FILE_NOT_FOUND:
            return HTTP_NOT_FOUND;

        /* Everything else is a server error, including the two timeouts, an
         * unknown client, and a host the allowlist refused. DimsOriginStatusMode
         * map is what moves the ones that came from the origin. */
        default:
            return HTTP_INTERNAL_SERVER_ERROR;
    }
}

const char *
dims_status_name(int status)
{
    switch (status) {
        case DIMS_IGNORE:                   return "ignore";
        case DIMS_SUCCESS:                  return "success";
        case DIMS_FAILURE:                  return "failure";
        case DIMS_DOWNLOAD_TIMEOUT:         return "download timeout";
        case DIMS_IMAGEMAGICK_TIMEOUT:      return "imagemagick timeout";
        case DIMS_BAD_CLIENT:               return "bad client";
        case DIMS_BAD_URL:                  return "bad url";
        case DIMS_BAD_ARGUMENTS:            return "bad arguments";
        case DIMS_HOSTNAME_NOT_IN_WHITELIST: return "hostname not in whitelist";
        case DIMS_FILE_NOT_FOUND:           return "file not found";
        case DIMS_NETWORK_REFUSED:          return "network guard refused the target";
        default:                            return "unknown";
    }
}

int
dims_origin_status(dims_request_rec *d)
{
    if (d->config->origin_status_mode != DIMS_ORIGIN_STATUS_MAP) {
        return 0;
    }

    switch (d->status) {
        case DIMS_FILE_NOT_FOUND:
            return HTTP_NOT_FOUND;

        case DIMS_DOWNLOAD_TIMEOUT:
            return HTTP_GATEWAY_TIME_OUT;

        case DIMS_FAILURE:
            /*
             * A failure the origin caused leaves its status on the request. A
             * failure after a successful fetch, such as a malformed geometry,
             * leaves 200 there, and it is the module's failure, not a bad
             * gateway. The module's own mapping keeps those.
             */
            return (d->fetch_http_status != 0 && d->fetch_http_status != HTTP_OK)
                    ? HTTP_BAD_GATEWAY : 0;

        default:
            /* Not a failure at the origin. */
            return 0;
    }
}
