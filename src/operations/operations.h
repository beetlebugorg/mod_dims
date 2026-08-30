/*
 * The image operations.
 *
 * One file per operation, matching the layout go-dims uses in
 * internal/commands. An operation reads the wand on the request, changes it,
 * and returns DIMS_SUCCESS or a failure code with a message.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_OPERATIONS_H
#define _DIMS_OPERATIONS_H

#include "../mod_dims.h"

#include <stdlib.h>

/*
 * Runs an ImageMagick call and returns from the operation when it fails.
 *
 * The timeout is checked first: the progress monitor sets the status when an
 * operation runs too long, and that has to be reported as a timeout rather
 * than a plain failure.
 */
#define MAGICK_CHECK(func, rec)                     \
    do {                                            \
        apr_status_t code = func;                   \
        if (rec->status == DIMS_IMAGEMAGICK_TIMEOUT) { \
            return DIMS_IMAGEMAGICK_TIMEOUT;        \
        } else if (code == MagickFalse) {           \
            return DIMS_FAILURE;                    \
        }                                           \
    } while (0)

/*
 * Runs a crop and returns a bad request when ImageMagick refuses it.
 *
 * The geometry checks above catch the regions go-dims names, and this catches
 * the rest. A region ImageMagick will not cut is the caller's geometry, not a
 * fault in the service, so it must not end the request with 500.
 */
#define MAGICK_CROP_CHECK(func, rec, err, message)  \
    do {                                            \
        apr_status_t code = func;                   \
        if (rec->status == DIMS_IMAGEMAGICK_TIMEOUT) { \
            return DIMS_IMAGEMAGICK_TIMEOUT;        \
        } else if (code == MagickFalse) {           \
            *(err) = (message);                     \
            return DIMS_BAD_ARGUMENTS;              \
        }                                           \
    } while (0)

#endif
