/*
 * The watermark overlay cache.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "overlay_cache.h"

#include <apr_file_info.h>
#include <apr_escape.h>
#include <apr_file_io.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <string.h>

#define DIMS_OVERLAY_CACHE_NAME "dims-cache"

char *
dims_overlay_cache_dir(apr_pool_t *pool, const char *tmp_dir)
{
    size_t length;

    if (tmp_dir == NULL || *tmp_dir == '\0') {
        tmp_dir = "/tmp";
    }

    length = strlen(tmp_dir);
    if (tmp_dir[length - 1] == '/') {
        return apr_pstrcat(pool, tmp_dir, DIMS_OVERLAY_CACHE_NAME "/", NULL);
    }

    return apr_pstrcat(pool, tmp_dir, "/", DIMS_OVERLAY_CACHE_NAME "/", NULL);
}

char *
dims_overlay_cache_path(apr_pool_t *pool, const char *cache_dir,
                        const char *overlay_url)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    char hex[SHA_DIGEST_LENGTH * 2 + 1];

    if (cache_dir == NULL || overlay_url == NULL) {
        return NULL;
    }

    SHA1((const unsigned char *) overlay_url, strlen(overlay_url), digest);

    if (apr_escape_hex(hex, digest, SHA_DIGEST_LENGTH, 0, NULL) != APR_SUCCESS) {
        return NULL;
    }

    return apr_pstrcat(pool, cache_dir, hex, NULL);
}

/* One entry, for the sort that decides what to drop. */
typedef struct {
    const char *path;
    apr_time_t mtime;
} dims_cache_entry;

static int
dims_oldest_first(const void *a, const void *b)
{
    apr_time_t left = ((const dims_cache_entry *) a)->mtime;
    apr_time_t right = ((const dims_cache_entry *) b)->mtime;

    if (left < right) {
        return -1;
    }

    return left > right;
}

void
dims_overlay_cache_prune(apr_pool_t *pool, const char *cache_dir,
                         int max_entries, apr_time_t max_age_seconds,
                         apr_time_t now)
{
    apr_array_header_t *entries;
    apr_finfo_t finfo;
    apr_dir_t *dir;
    apr_time_t oldest_allowed;
    int i, excess;

    if (cache_dir == NULL || (max_entries <= 0 && max_age_seconds <= 0)) {
        return;
    }

    if (apr_dir_open(&dir, cache_dir, pool) != APR_SUCCESS) {
        return;
    }

    entries = apr_array_make(pool, 64, sizeof(dims_cache_entry));
    oldest_allowed = now - apr_time_from_sec(max_age_seconds);

    while (apr_dir_read(&finfo, APR_FINFO_NAME | APR_FINFO_TYPE | APR_FINFO_MTIME,
                        dir) == APR_SUCCESS) {
        dims_cache_entry *entry;
        char *path;

        if (finfo.filetype != APR_REG) {
            continue;
        }

        path = apr_pstrcat(pool, cache_dir, finfo.name, NULL);

        if (max_age_seconds > 0 && finfo.mtime < oldest_allowed) {
            apr_file_remove(path, pool);
            continue;
        }

        entry = (dims_cache_entry *) apr_array_push(entries);
        entry->path = path;
        entry->mtime = finfo.mtime;
    }

    apr_dir_close(dir);

    excess = entries->nelts - max_entries;
    if (max_entries <= 0 || excess <= 0) {
        return;
    }

    qsort(entries->elts, (size_t) entries->nelts, sizeof(dims_cache_entry),
          dims_oldest_first);

    for (i = 0; i < excess; i++) {
        apr_file_remove(((dims_cache_entry *) entries->elts)[i].path, pool);
    }
}
