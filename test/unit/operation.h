/*
 * The shape every operation case shares: load a fixture, run one operation,
 * assert the named properties, compare bytes.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_OPERATION_H
#define DIMS_TEST_OPERATION_H

#include "fixture.h"
#include "../lib/golden.h"
#include "../lib/test.h"

/*
 * Runs one operation and compares the result.
 *
 * name is the go-dims test name. The golden file is
 * "unit.<fixture stem>.<name>", separate from the HTTP layer's file: the two
 * layers encode through different paths, so their bytes are not the same
 * image written twice.
 *
 * Pass -1 for a dimension that is not asserted.
 */
void dims_run_operation(const char *name, const char *image,
                        dims_operation_func *operation, const char *args,
                        long want_width, long want_height);

/* The same, for a case that supplies a query string, such as watermark. */
void dims_run_operation_with_query(const char *name, const char *image,
                                   dims_operation_func *operation, const char *args,
                                   const char *query, long want_width,
                                   long want_height);

/* Runs an operation and returns its status without comparing bytes. */
apr_status_t dims_operation_status(const char *image, dims_operation_func *operation,
                                   const char *args);

/* The same, with a query string. */
apr_status_t dims_operation_status_with_query(const char *image,
                                             dims_operation_func *operation,
                                             const char *args, const char *query);

#endif
