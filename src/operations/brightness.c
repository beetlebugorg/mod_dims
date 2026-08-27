/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"

apr_status_t
dims_brightness_operation (dims_request_rec *d, char *args, const char **err) {
    GeometryInfo geometry;

    (void) ParseGeometry(args, &geometry);

    MAGICK_CHECK(MagickBrightnessContrastImage(d->wand,
            geometry.rho, geometry.sigma), d);

    return DIMS_SUCCESS;
}
