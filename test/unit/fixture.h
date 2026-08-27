/*
 * Builds the dims_request_rec an operation expects, on a standalone APR pool.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_FIXTURE_H
#define DIMS_TEST_FIXTURE_H

#include "mod_dims.h"

/* Call once before any case. */
void dims_fixture_init(void);

/*
 * Loads a fixture image and returns a request ready for an operation.
 *
 * query is the value of r->args, which the watermark command reads, or NULL.
 * The caller releases it with dims_fixture_free.
 */
dims_request_rec *dims_fixture_request(const char *image, const char *query);

void dims_fixture_free(dims_request_rec *d);

/*
 * Encodes the wand and returns the bytes. The caller frees them with
 * MagickRelinquishMemory. Sets *length.
 */
unsigned char *dims_fixture_export(dims_request_rec *d, size_t *length);

/* The extension for the wand's current format, for example ".png". */
const char *dims_fixture_extension(dims_request_rec *d);

#endif
