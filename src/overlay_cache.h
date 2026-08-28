/*
 * The watermark overlay cache.
 *
 * An overlay is fetched once and kept on disk under a name derived from its
 * URL. The cache is bounded by entry count and by age, because no signature covers the overlay URL and any
 * caller can add to it.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_OVERLAY_CACHE_H
#define _DIMS_OVERLAY_CACHE_H

#include "mod_dims.h"

/*
 * The cache directory, with exactly one separator between the temporary
 * directory and the name.
 *
 * TMPDIR and P_tmpdir both usually end without a slash, so a plain
 * concatenation names a sibling of the temporary directory rather than a
 * child of it.
 */
char *dims_overlay_cache_dir(apr_pool_t *pool, const char *tmp_dir);

/*
 * The path an overlay is cached at.
 *
 * The name is a digest of the whole URL. A digest of the last path segment
 * lets two overlays on different hosts share one entry, which any caller can
 * use to serve their image in place of another's.
 */
char *dims_overlay_cache_path(apr_pool_t *pool, const char *cache_dir,
                              const char *overlay_url);

/*
 * Deletes expired and excess entries.
 *
 * max_age is in seconds and max_entries is a count. Zero turns either bound
 * off. The oldest entries go first.
 */
void dims_overlay_cache_prune(apr_pool_t *pool, const char *cache_dir,
                              int max_entries, apr_time_t max_age_seconds,
                              apr_time_t now);

#endif
