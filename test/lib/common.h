/*
 * The shape every operation case shares: sign a /dims4/ URL, request it,
 * assert the named properties, then compare bytes.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_COMMON_H
#define DIMS_TEST_COMMON_H

#include "golden.h"
#include "imagesize.h"
#include "request.h"
#include "signing.h"
#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The URL of a fixture on the origin service. Caller frees. */
char *dims_fixture_url(const char *fixture);

/*
 * Requests commands against a fixture over /dims4/ and returns the response.
 * The caller frees it with dims_response_free.
 */
dims_response *dims_request_ops(const char *commands, const char *fixture);

/*
 * The whole shape in one call. Requests commands against the fixture, asserts
 * a 200 and the expected dimensions, then compares bytes against
 * "<fixture stem>.<name>". Pass -1 for a dimension that is not asserted.
 */
void dims_run_golden(const char *name, const char *fixture, const char *commands,
                     long want_width, long want_height);

#endif
