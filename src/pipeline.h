/*
 * The image pipeline.
 *
 * What happens to a request once the handler has worked out which image to
 * fetch and confirmed the caller may ask for it.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_PIPELINE_H
#define _DIMS_PIPELINE_H

#include "mod_dims.h"

/*
 * Runs an ImageMagick call and returns the error image when it fails.
 *
 * Unlike the macro of the same name in the operations, this one sends a
 * response, because the handlers it serves have nowhere else to report to.
 */
#define MAGICK_CHECK(func, d)                          \
    do {                                               \
        if (func == MagickFalse)                       \
            return dims_cleanup(d, NULL, DIMS_FAILURE); \
        if (d->status == DIMS_IMAGEMAGICK_TIMEOUT)     \
            return dims_cleanup(d, NULL, d->status);   \
    } while (0);

/*
 * The command name to operation table, built once per process at startup.
 *
 * A shared global rather than something on the request, because it is the same
 * for every request and building it per request would be wasted work.
 */
extern apr_hash_t *ops;

/* Parses the command string and runs each operation, then sends the result. */
apr_status_t dims_process_image(dims_request_rec *d);

/*
 * Draws a solid image in the configured colour, at the size the request asked
 * for. Returns zero when it cannot.
 */
int dims_draw_error_image(dims_request_rec *d);

/* Frees the wand, logs the reason, and sends the error image when one is
 * configured. */
apr_status_t dims_cleanup(dims_request_rec *d, const char *err_msg, int status);

/* Releases the wand. Safe to call more than once. */
void dims_free_request(dims_request_rec *d);

/* Downloads url into the request's wand. Passing NULL fetches the error
 * image instead. */
int dims_fetch_remote_image(dims_request_rec *d, const char *url);

/* Tells ImageMagick the size the request will end at, so a large JPEG decodes
 * at a smaller scale. */
void dims_set_optimal_geometry(dims_request_rec *d);

#endif
