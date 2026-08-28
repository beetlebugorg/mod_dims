/*
 * The request handlers.
 *
 * httpd calls dims_handler for every request whose handler name mod_dims
 * claims. It works out which endpoint was asked for, parses the URL into a
 * dims_request_rec, and hands that to the image pipeline.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_HANDLER_H
#define _DIMS_HANDLER_H

#include "mod_dims.h"

/* The entry point httpd calls. */
apr_status_t dims_handler(request_rec *r);

/* Validates the client and the signature, fetches the source, and runs the
 * pipeline. Both the legacy and the current endpoints end up here. */
apr_status_t dims_handle_request(dims_request_rec *d);

/* Answers /dims-sizer/ with the source image dimensions. */
apr_status_t dims_sizer(dims_request_rec *d);

#endif
