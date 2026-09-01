/*
 * The status endpoint and the counters it reports.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_STATUS_H
#define _DIMS_STATUS_H

#include "mod_dims.h"

/* Answers /dims-status/. */
apr_status_t dims_status_handler(request_rec *r);

#endif
