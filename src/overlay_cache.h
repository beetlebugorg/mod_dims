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

/*
 * The decoded overlay cache.
 *
 * The disk cache holds the overlay bytes. Every watermark request reads those
 * bytes and decodes them again, which is the slow step. This second cache
 * holds the decoded overlay in process memory, so a repeat request clones it
 * and skips the decode.
 *
 * The cache is shared by every worker thread. It clones the overlay under a
 * lock, because one ImageMagick wand is not safe for two threads at once. It
 * holds a small, fixed number of overlays, because a decoded overlay is large.
 */

/* A decoded overlay is large, so the memory cache stays small even when the
 * disk cache holds many entries. */
#define DIMS_OVERLAY_MEMCACHE_MAX_ENTRIES 32

/*
 * Creates the process memory overlay cache. Call it once per child.
 *
 * max_entries caps the count. max_age_seconds expires an entry, and 0 keeps it
 * for the life of the process. A second call does nothing.
 */
void dims_overlay_memcache_init(apr_pool_t *pool, int max_entries,
                                long max_age_seconds);

/*
 * Returns a private clone of the decoded overlay for the URL, or NULL on a
 * miss. The caller owns the clone and must destroy it.
 */
MagickWand *dims_overlay_memcache_get(const char *url);

/*
 * Stores a clone of the decoded overlay for the URL. The caller keeps the
 * wand. The oldest entry goes when the cache is full.
 */
void dims_overlay_memcache_put(const char *url, MagickWand *wand);

/*
 * Frees every cached overlay and the cache. A test calls it. The module lets
 * the process exit reclaim the cache.
 */
void dims_overlay_memcache_destroy(void);

#endif
