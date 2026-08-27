/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"

apr_status_t
dims_flipflop_operation (dims_request_rec *d, char *args, const char **err) {
    if(args != NULL) {
        if(strcmp(args, "horizontal") == 0) {
            MAGICK_CHECK(MagickFlopImage(d->wand), d);
        } else if (strcmp(args, "vertical") == 0) {
            MAGICK_CHECK(MagickFlipImage(d->wand), d);
        }
    }

    return DIMS_SUCCESS;
}
