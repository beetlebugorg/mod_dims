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

        /* Everything else reports as a server error, including the two
         * timeouts, an unknown client, and a host the allowlist refused.
         *
         * Three of those are arguably wrong. A timeout is a gateway problem,
         * an unknown client is a bad request, and a refused host is neither.
         * Changing them changes what a caller sees, so it waits for the
         * directive that lets an operator opt in. */
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
