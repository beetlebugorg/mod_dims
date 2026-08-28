/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"

apr_status_t
dims_strip_operation (dims_request_rec *d, char *args, const char **err) {

    /* If args is passed from the user and 
     *   a) it equals true, strip the image.
     *   b) it equals false, don't strip the image.
     *   c) it is neither true/false, strip based on config value.
     * If args is NULL, strip based on config value.
     */
    if(args != NULL) {
        if(strcmp(args, "true") == 0 || ( strcmp(args, "false") != 0 && d->config->strip_metadata )) {
            MAGICK_CHECK(MagickStripImage(d->wand), d);
        }
    }
    else if(d->config->strip_metadata) {
        MAGICK_CHECK(MagickStripImage(d->wand), d);
    }

    return DIMS_SUCCESS;
}
