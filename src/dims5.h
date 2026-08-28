/*
 * The /dims5/ endpoint.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_DIMS5_H
#define _DIMS_DIMS5_H

#include "mod_dims.h"

/* The length of "/dims5/". */
#define DIMS5_PREFIX_LEN 7

/*
 * Reads a /dims5/ request and checks its signature.
 *
 * Sets the commands and the image URL on the request. Returns DIMS_SUCCESS,
 * or the status to answer with.
 */
apr_status_t dims5_verify(dims_request_rec *d);

#endif
