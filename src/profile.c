/*
 * The ICC profiles that convert a CMYK source to RGB.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "profile.h"

#include <apr_file_info.h>
#include <apr_file_io.h>

/* The names in the profile directory. */
#define DIMS_PROFILE_CMYK "CGATS21_CRPC2.icc"
#define DIMS_PROFILE_RGB "sRGB.icc"

static dims_profile cmyk_profile;
static dims_profile rgb_profile;

static void
read_profile(apr_pool_t *pool, server_rec *s, const char *dir, const char *name,
             dims_profile *into)
{
    const char *path = apr_pstrcat(pool, dir, "/", name, NULL);
    apr_finfo_t finfo;
    apr_file_t *file;
    apr_size_t length;

    into->data = NULL;
    into->length = 0;

    if (apr_stat(&finfo, path, APR_FINFO_SIZE, pool) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "mod_dims cannot read the colour profile at %s. A CMYK "
                     "source with no profile of its own will not convert. Set "
                     "DimsProfileDir to where the profiles are.", path);
        return;
    }

    if (apr_file_open(&file, path, APR_FOPEN_READ | APR_FOPEN_BINARY,
                      APR_FPROT_OS_DEFAULT, pool) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "mod_dims cannot open the colour profile at %s.", path);
        return;
    }

    length = (apr_size_t) finfo.size;
    into->data = apr_palloc(pool, length);

    if (apr_file_read_full(file, into->data, length, NULL) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "mod_dims cannot read the colour profile at %s.", path);
        into->data = NULL;
        into->length = 0;
    } else {
        into->length = length;
    }

    apr_file_close(file);
}

void
dims_profiles_load(apr_pool_t *pool, server_rec *s, const char *dir)
{
    read_profile(pool, s, dir, DIMS_PROFILE_CMYK, &cmyk_profile);
    read_profile(pool, s, dir, DIMS_PROFILE_RGB, &rgb_profile);
}

const dims_profile *
dims_profile_cmyk(void)
{
    return &cmyk_profile;
}

const dims_profile *
dims_profile_rgb(void)
{
    return &rgb_profile;
}
