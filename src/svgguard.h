/*
 * Guarding an SVG source against an external reference.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_SVGGUARD_H
#define _DIMS_SVGGUARD_H

#include <apr_pools.h>

/*
 * Reports whether a fetched source is safe to hand to ImageMagick.
 *
 * A source that does not look like SVG is safe. An SVG that parses and holds no
 * external reference is safe. An SVG that references an external resource is
 * not safe, and neither is one that does not parse. ImageMagick reads a local
 * file named by an <image> href, so an external reference is refused before the
 * renderer sees it.
 *
 * reason receives a short description when the result is not safe. It may be
 * NULL.
 */
int dims_svg_is_safe(apr_pool_t *pool, const char *data, apr_size_t len,
                     const char **reason);

#endif
