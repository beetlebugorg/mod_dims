/*
 * Reading a source URL out of a request.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_URL_H
#define _DIMS_URL_H

#include <apr_pools.h>
#include <apr_strings.h>

/*
 * Finds the source URL inside a request path.
 *
 * The legacy handlers carry the URL in the path, and httpd collapses the
 * double slash, so it arrives as "http:/example.com/a.jpg". This returns it
 * with the slash put back, or NULL when the path carries no URL.
 *
 * Sets *start to where the URL begins inside subject, which is where the
 * caller truncates to leave only the commands. Pass NULL to skip it.
 */
char *dims_path_image_url(apr_pool_t *pool, char *subject, char **start);

/*
 * Returns the value of one query parameter, or NULL when the token names a
 * different parameter.
 *
 * name carries its own equals sign, for example "eurl=". The whole name is
 * compared, so a token shorter than the name never matches.
 */
const char *dims_param_value(const char *token, const char *name);

/* The length of "/dims3/" and of "/dims4/". */
#define DIMS_ENDPOINT_PREFIX_LEN 7

/* Whether a URI begins with the location the dims3 and dims4 handlers read
 * their commands from. */
int dims_endpoint_prefix(const char *uri);

#endif
