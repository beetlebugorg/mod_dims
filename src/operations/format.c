/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"

apr_status_t
dims_format_operation (dims_request_rec *d, char *args, const char **err) {
    MAGICK_CHECK(MagickSetImageFormat(d->wand, args), d);
    return DIMS_SUCCESS;
}
