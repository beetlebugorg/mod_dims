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

/*
 * Request counters, kept in shared memory so every worker adds to the same
 * ones and the status endpoint reports a whole server rather than whichever
 * worker answered.
 */
typedef struct {
    apr_uint32_t success_count;
    apr_uint32_t failure_count;
    apr_uint32_t download_timeout_count;
    apr_uint32_t imagemagick_timeout_count;
} dims_stats_rec;

extern dims_stats_rec *stats;
extern apr_shm_t *shm;

/* Answers /dims-status/. */
apr_status_t dims_status_handler(request_rec *r);

#endif
