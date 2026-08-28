/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"

/* What MagickSetImageCompressionQuality accepts. */
#define DIMS_QUALITY_MIN 1
#define DIMS_QUALITY_MAX 100

apr_status_t
dims_quality_operation (dims_request_rec *d, char *args, const char **err) {
    int existing_quality;
    char *end = NULL;
    long value;

    if (args == NULL) {
        *err = "Quality requires a value";
        return DIMS_BAD_ARGUMENTS;
    }

    /* Base 10, so a leading zero is not octal. */
    value = strtol(args, &end, 10);

    if (end == args || *end != '\0' ||
            value < DIMS_QUALITY_MIN || value > DIMS_QUALITY_MAX) {
        *err = "Quality must be a number from 1 to 100";
        return DIMS_BAD_ARGUMENTS;
    }

    existing_quality = MagickGetImageCompressionQuality(d->wand);

    if(value < existing_quality || existing_quality == 0) {
        MAGICK_CHECK(MagickSetImageCompressionQuality(d->wand, (size_t) value), d);
    }
    return DIMS_SUCCESS;
}
