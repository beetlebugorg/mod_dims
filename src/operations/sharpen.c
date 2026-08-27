/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"

apr_status_t
dims_sharpen_operation (dims_request_rec *d, char *args, const char **err) {
    MagickStatusType flags;
    GeometryInfo geometry;

    flags = ParseGeometry(args, &geometry);
    if ((flags & SigmaValue) == 0) {
        geometry.sigma=1.0;
    }

    MAGICK_CHECK(MagickSharpenImage(d->wand, geometry.rho, geometry.sigma), d);

    return DIMS_SUCCESS;
}
