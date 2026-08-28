/*
 * The ICC profiles that convert a CMYK source to RGB.
 *
 * They are files rather than arrays compiled into the module, because the
 * terms both of them ship under require that they are not altered.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_PROFILE_H
#define _DIMS_PROFILE_H

#include "mod_dims.h"

/* One profile, read once per process. */
typedef struct {
    unsigned char *data;
    apr_size_t length;
} dims_profile;

/*
 * Reads both profiles from dir into pool. Logs and leaves a profile empty
 * when its file is missing, because a CMYK source is the only request that
 * needs one.
 */
void dims_profiles_load(apr_pool_t *pool, server_rec *s, const char *dir);

/* The source profile assumed for a CMYK image with none of its own. */
const dims_profile *dims_profile_cmyk(void);

/* The profile every converted image ends in. */
const dims_profile *dims_profile_rgb(void);

#endif
