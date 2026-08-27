/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"

apr_status_t
dims_quality_operation (dims_request_rec *d, char *args, const char **err) {
    int quality = apr_strtoi64(args, NULL, 0);
    int existing_quality = MagickGetImageCompressionQuality(d->wand);

    if(quality < existing_quality || existing_quality == 0) {
        MAGICK_CHECK(MagickSetImageCompressionQuality(d->wand, quality), d);
    }
    return DIMS_SUCCESS;
}
