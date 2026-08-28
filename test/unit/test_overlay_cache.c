/*
 * The watermark overlay cache.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "overlay_cache.h"
#include "../lib/test.h"

#include <apr_file_io.h>
#include <apr_general.h>
#include <apr_strings.h>
#include <string.h>

static apr_pool_t *
cache_pool(void)
{
    static apr_pool_t *pool;

    if (pool == NULL && apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        FAIL("cannot create a pool");
    }

    return pool;
}

/*
 * TMPDIR and P_tmpdir both usually end without a slash, so a plain
 * concatenation names a sibling of the temporary directory: /tmp becomes
 * /tmpdims-cache/ at the filesystem root, which a worker cannot create.
 */
static void
test_cache_dir_has_one_separator(void)
{
    apr_pool_t *pool = cache_pool();

    CHECK(strcmp(dims_overlay_cache_dir(pool, "/tmp"), "/tmp/dims-cache/") == 0,
          "a directory with no trailing slash, got %s",
          dims_overlay_cache_dir(pool, "/tmp"));
    CHECK(strcmp(dims_overlay_cache_dir(pool, "/tmp/"), "/tmp/dims-cache/") == 0,
          "a directory with one, got %s", dims_overlay_cache_dir(pool, "/tmp/"));
    CHECK(strcmp(dims_overlay_cache_dir(pool, NULL), "/tmp/dims-cache/") == 0,
          "no directory at all, got %s", dims_overlay_cache_dir(pool, NULL));
    CHECK(strcmp(dims_overlay_cache_dir(pool, ""), "/tmp/dims-cache/") == 0,
          "an empty directory, got %s", dims_overlay_cache_dir(pool, ""));
}

/*
 * The name covers the whole URL. A name covering the last path segment lets
 * two overlays on different hosts share one entry, and any caller can pick the
 * segment.
 */
static void
test_cache_path_covers_the_whole_url(void)
{
    apr_pool_t *pool = cache_pool();
    const char *dir = "/tmp/dims-cache/";
    char *first = dims_overlay_cache_path(pool, dir, "http://a.example/logo.png");
    char *second = dims_overlay_cache_path(pool, dir, "http://b.example/logo.png");
    char *again = dims_overlay_cache_path(pool, dir, "http://a.example/logo.png");

    CHECK(first != NULL && second != NULL, "both paths");
    CHECK(strcmp(first, second) != 0,
          "two hosts sharing a filename must not share an entry");
    CHECK(strcmp(first, again) == 0, "the same URL names the same entry");
    CHECK(strncmp(first, dir, strlen(dir)) == 0, "the entry sits in the cache");
    CHECK(dims_overlay_cache_path(pool, dir, NULL) == NULL, "no URL");
    CHECK(dims_overlay_cache_path(pool, NULL, "http://a/x.png") == NULL,
          "no directory");
}

/* Builds a cache directory holding count files, each aged by its index. */
static const char *
seed(apr_pool_t *pool, const char *name, int count, apr_time_t now)
{
    const char *dir = apr_pstrcat(pool, "/tmp/", name, "/", NULL);
    int i;

    apr_dir_make_recursive(dir, APR_FPROT_UREAD | APR_FPROT_UWRITE |
            APR_FPROT_UEXECUTE, pool);

    for (i = 0; i < count; i++) {
        const char *path = apr_psprintf(pool, "%sentry%02d", dir, i);
        apr_file_t *file;

        if (apr_file_open(&file, path, APR_FOPEN_CREATE | APR_FOPEN_WRITE |
                APR_FOPEN_TRUNCATE, APR_FPROT_UREAD | APR_FPROT_UWRITE,
                pool) == APR_SUCCESS) {
            apr_file_close(file);
        }

        /* Entry 0 is the oldest. */
        apr_file_mtime_set(path, now - apr_time_from_sec(100 - i), pool);
    }

    return dir;
}

static int
count_entries(apr_pool_t *pool, const char *dir)
{
    apr_finfo_t finfo;
    apr_dir_t *handle;
    int found = 0;

    if (apr_dir_open(&handle, dir, pool) != APR_SUCCESS) {
        return -1;
    }

    while (apr_dir_read(&finfo, APR_FINFO_NAME | APR_FINFO_TYPE, handle) ==
            APR_SUCCESS) {
        if (finfo.filetype == APR_REG) {
            found++;
        }
    }

    apr_dir_close(handle);

    return found;
}

static int
has_entry(apr_pool_t *pool, const char *dir, const char *name)
{
    apr_finfo_t finfo;

    return apr_stat(&finfo, apr_pstrcat(pool, dir, name, NULL),
                    APR_FINFO_TYPE, pool) == APR_SUCCESS;
}

static void
test_prune_drops_the_oldest_over_the_count(void)
{
    apr_pool_t *pool = cache_pool();
    apr_time_t now = apr_time_now();
    const char *dir = seed(pool, "dims-prune-count", 10, now);

    dims_overlay_cache_prune(pool, dir, 4, 0, now);

    CHECK_INT(count_entries(pool, dir), 4, "entries left");
    CHECK(!has_entry(pool, dir, "entry00"), "the oldest goes");
    CHECK(has_entry(pool, dir, "entry09"), "the newest stays");
}

static void
test_prune_drops_what_is_too_old(void)
{
    apr_pool_t *pool = cache_pool();
    apr_time_t now = apr_time_now();
    const char *dir = seed(pool, "dims-prune-age", 10, now);

    /* Entry i is 100 - i seconds old, and the bound is inclusive, so 94
     * seconds keeps entries 6 to 9. */
    dims_overlay_cache_prune(pool, dir, 0, 94, now);

    CHECK_INT(count_entries(pool, dir), 4, "entries left");
    CHECK(!has_entry(pool, dir, "entry05"), "95 seconds old goes");
    CHECK(has_entry(pool, dir, "entry06"), "94 seconds old stays");
}

/* Zero for both bounds keeps everything, which is what an operator sets to
 * turn the cache bound off. */
static void
test_prune_without_bounds_keeps_everything(void)
{
    apr_pool_t *pool = cache_pool();
    apr_time_t now = apr_time_now();
    const char *dir = seed(pool, "dims-prune-none", 6, now);

    dims_overlay_cache_prune(pool, dir, 0, 0, now);

    CHECK_INT(count_entries(pool, dir), 6, "entries left");
}

static void
test_prune_survives_a_missing_directory(void)
{
    apr_pool_t *pool = cache_pool();

    dims_overlay_cache_prune(pool, "/tmp/dims-cache-not-here/", 4, 60,
                             apr_time_now());
    dims_overlay_cache_prune(pool, NULL, 4, 60, apr_time_now());
}

/* A small decoded overlay to store and clone. */
static MagickWand *
sample_overlay(unsigned int width, unsigned int height)
{
    PixelWand *background = NewPixelWand();
    MagickWand *wand = NewMagickWand();

    PixelSetColor(background, "red");

    if (MagickNewImage(wand, width, height, background) == MagickFalse) {
        FAIL("cannot create a sample overlay");
    }

    DestroyPixelWand(background);

    return wand;
}

/* A hit hands back a private copy, not the stored wand. */
static void
test_memcache_returns_an_independent_clone(void)
{
    MagickWand *source;
    MagickWand *clone;

    dims_overlay_memcache_destroy();
    dims_overlay_memcache_init(cache_pool(), 4, 0);

    source = sample_overlay(7, 5);
    dims_overlay_memcache_put("https://example.com/logo.png", source);

    clone = dims_overlay_memcache_get("https://example.com/logo.png");

    CHECK(clone != NULL, "a stored overlay is a hit");
    CHECK(clone != source, "the hit is a clone, not the stored wand");
    CHECK_INT(MagickGetImageWidth(clone), 7, "clone width");
    CHECK_INT(MagickGetImageHeight(clone), 5, "clone height");

    DestroyMagickWand(clone);
    DestroyMagickWand(source);
    dims_overlay_memcache_destroy();
}

/* An overlay the cache never saw is a miss. */
static void
test_memcache_misses_an_unknown_url(void)
{
    dims_overlay_memcache_destroy();
    dims_overlay_memcache_init(cache_pool(), 4, 0);

    CHECK(dims_overlay_memcache_get("https://example.com/absent.png") == NULL,
          "an unknown overlay is a miss");

    dims_overlay_memcache_destroy();
}

/* The cache holds its count. The oldest overlay goes first. */
static void
test_memcache_bounds_the_count(void)
{
    MagickWand *wand = sample_overlay(4, 4);
    MagickWand *hit;

    dims_overlay_memcache_destroy();
    dims_overlay_memcache_init(cache_pool(), 2, 0);

    dims_overlay_memcache_put("a", wand);
    dims_overlay_memcache_put("b", wand);
    dims_overlay_memcache_put("c", wand);

    CHECK(dims_overlay_memcache_get("a") == NULL, "the oldest overlay is gone");

    hit = dims_overlay_memcache_get("b");
    CHECK(hit != NULL, "the second overlay stays");
    DestroyMagickWand(hit);

    hit = dims_overlay_memcache_get("c");
    CHECK(hit != NULL, "the newest overlay stays");
    DestroyMagickWand(hit);

    DestroyMagickWand(wand);
    dims_overlay_memcache_destroy();
}

/* Without a cache the calls do nothing and answer a miss. */
static void
test_memcache_without_init_is_a_miss(void)
{
    MagickWand *wand = sample_overlay(4, 4);

    dims_overlay_memcache_destroy();

    dims_overlay_memcache_put("a", wand);
    CHECK(dims_overlay_memcache_get("a") == NULL, "no cache is a miss");

    DestroyMagickWand(wand);
}

const dims_test dims_tests_unit_overlay_cache[] = {
    { "TestCacheDirHasOneSeparator", test_cache_dir_has_one_separator,
      NULL },
    { "TestCachePathCoversTheWholeUrl", test_cache_path_covers_the_whole_url,
      NULL },
    { "TestPruneDropsTheOldestOverTheCount",
      test_prune_drops_the_oldest_over_the_count, NULL },
    { "TestPruneDropsWhatIsTooOld", test_prune_drops_what_is_too_old, NULL },
    { "TestPruneWithoutBoundsKeepsEverything",
      test_prune_without_bounds_keeps_everything, NULL },
    { "TestPruneSurvivesAMissingDirectory",
      test_prune_survives_a_missing_directory, NULL },
    { "TestMemcacheReturnsAnIndependentClone",
      test_memcache_returns_an_independent_clone, NULL },
    { "TestMemcacheMissesAnUnknownUrl",
      test_memcache_misses_an_unknown_url, NULL },
    { "TestMemcacheBoundsTheCount", test_memcache_bounds_the_count, NULL },
    { "TestMemcacheWithoutInitIsAMiss",
      test_memcache_without_init_is_a_miss, NULL },
    DIMS_TEST_END
};
