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
 * The legacy handlers carry the URL in the path rather than in a query
 * parameter, and httpd collapses the double slash on the way in, so the URL
 * arrives as "http:/example.com/a.jpg". This returns it with the slash put
 * back.
 *
 * Sets *start to where the URL begins inside subject, which is where the
 * caller truncates to leave only the commands. Pass NULL when the position
 * does not matter.
 *
 * Returns NULL when the path carries no URL.
 */
char *dims_path_image_url(apr_pool_t *pool, char *subject, char **start);

#endif
