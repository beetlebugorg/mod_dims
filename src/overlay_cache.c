/*
 * The watermark overlay cache.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "overlay_cache.h"
#include "metrics.h"

#include <apr_file_info.h>
#include <apr_escape.h>
#include <apr_file_io.h>
#include <apr_thread_mutex.h>
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

/* -- The decoded overlay cache -------------------------------------------- */

/* One decoded overlay. A NULL url marks a free slot. */
typedef struct {
    char *url;
    MagickWand *wand;
    apr_time_t inserted;
    apr_uint64_t used;
} dims_overlay_mementry;

typedef struct {
    apr_thread_mutex_t *mutex;
    dims_overlay_mementry *entries;
    int capacity;

    /* Zero keeps an entry for the life of the process. */
    apr_time_t max_age;

    /* Rises on every access. The smallest value names the oldest entry. */
    apr_uint64_t clock;
} dims_overlay_memcache;

static dims_overlay_memcache *overlay_memcache = NULL;

void
dims_overlay_memcache_init(apr_pool_t *pool, int max_entries,
                           long max_age_seconds)
{
    dims_overlay_memcache *cache;

    if (overlay_memcache != NULL || pool == NULL || max_entries <= 0) {
        return;
    }

    cache = calloc(1, sizeof(*cache));
    if (cache == NULL) {
        return;
    }

    cache->entries = calloc((size_t) max_entries, sizeof(*cache->entries));
    if (cache->entries == NULL) {
        free(cache);
        return;
    }

    if (apr_thread_mutex_create(&cache->mutex, APR_THREAD_MUTEX_DEFAULT,
                                pool) != APR_SUCCESS) {
        free(cache->entries);
        free(cache);
        return;
    }

    cache->capacity = max_entries;
    cache->max_age = (max_age_seconds > 0)
            ? apr_time_from_sec(max_age_seconds) : 0;
    cache->clock = 0;

    overlay_memcache = cache;
}

MagickWand *
dims_overlay_memcache_get(const char *url)
{
    dims_overlay_memcache *cache = overlay_memcache;
    MagickWand *clone = NULL;
    int expired = 0;
    int i;

    if (cache == NULL || url == NULL) {
        return NULL;
    }

    apr_thread_mutex_lock(cache->mutex);

    for (i = 0; i < cache->capacity; i++) {
        dims_overlay_mementry *entry = &cache->entries[i];

        if (entry->url == NULL || strcmp(entry->url, url) != 0) {
            continue;
        }

        /* An entry past its age is a miss. Drop it and let the caller decode
         * the overlay again. */
        if (cache->max_age > 0
                && apr_time_now() - entry->inserted > cache->max_age) {
            DestroyMagickWand(entry->wand);
            free(entry->url);
            entry->url = NULL;
            entry->wand = NULL;
            expired = 1;
            break;
        }

        entry->used = ++cache->clock;

        /* Clone under the lock. The stored wand is never handed out, so no
         * two threads read it at once. */
        clone = CloneMagickWand(entry->wand);
        break;
    }

    apr_thread_mutex_unlock(cache->mutex);

    /* An entry past its age reports separately from a name the cache never
     * held, because the two point at different settings. */
    dims_metrics_overlay_lookup(expired ? 2 : (clone != NULL) ? 0 : 1);

    return clone;
}

void
dims_overlay_memcache_put(const char *url, MagickWand *wand)
{
    dims_overlay_memcache *cache = overlay_memcache;
    dims_overlay_mementry *slot = NULL;
    char *key;
    MagickWand *stored;
    int i;

    if (cache == NULL || url == NULL || wand == NULL) {
        return;
    }

    apr_thread_mutex_lock(cache->mutex);

    /* Another thread that also missed may have stored it first. Keep the first
     * entry and add nothing. */
    for (i = 0; i < cache->capacity; i++) {
        if (cache->entries[i].url != NULL
                && strcmp(cache->entries[i].url, url) == 0) {
            apr_thread_mutex_unlock(cache->mutex);
            return;
        }
    }

    /* Take a free slot, or the oldest full one. */
    for (i = 0; i < cache->capacity; i++) {
        if (cache->entries[i].url == NULL) {
            slot = &cache->entries[i];
            break;
        }
        if (slot == NULL || cache->entries[i].used < slot->used) {
            slot = &cache->entries[i];
        }
    }

    key = strdup(url);
    stored = CloneMagickWand(wand);

    if (key == NULL || stored == NULL) {
        free(key);
        if (stored != NULL) {
            DestroyMagickWand(stored);
        }
        apr_thread_mutex_unlock(cache->mutex);
        return;
    }

    /* The slot held another overlay, so storing this one drops it. */
    if (slot->url != NULL) {
        DestroyMagickWand(slot->wand);
        free(slot->url);
        dims_metrics_overlay_eviction();
    }

    slot->url = key;
    slot->wand = stored;
    slot->inserted = apr_time_now();
    slot->used = ++cache->clock;

    apr_thread_mutex_unlock(cache->mutex);
}

void
dims_overlay_memcache_destroy(void)
{
    dims_overlay_memcache *cache = overlay_memcache;
    int i;

    if (cache == NULL) {
        return;
    }

    overlay_memcache = NULL;

    for (i = 0; i < cache->capacity; i++) {
        if (cache->entries[i].url != NULL) {
            DestroyMagickWand(cache->entries[i].wand);
            free(cache->entries[i].url);
        }
    }

    apr_thread_mutex_destroy(cache->mutex);
    free(cache->entries);
    free(cache);
}
