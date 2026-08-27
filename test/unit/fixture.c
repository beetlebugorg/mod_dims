/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fixture.h"
#include "stub_httpd.h"
#include "../lib/test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
dims_fixture_init(void)
{
    apr_initialize();
    atexit(apr_terminate);
    MagickWandGenesis();
    atexit(MagickWandTerminus);
}

dims_request_rec *
dims_fixture_request(const char *image, const char *query)
{
    apr_pool_t *pool = NULL;
    dims_request_rec *d;
    request_rec *r;
    dims_config_rec *config;
    dims_client_config_rec *client;
    char path[1024];

    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        FAIL("cannot create a pool");
        return NULL;
    }

    /* apr_pcalloc, not apr_palloc: an operation must not read a field this
     * harness forgot to set. Finding H8 is the same mistake in the module. */
    d = apr_pcalloc(pool, sizeof(*d));
    r = apr_pcalloc(pool, sizeof(*r));
    config = apr_pcalloc(pool, sizeof(*config));
    client = apr_pcalloc(pool, sizeof(*client));

    r->pool = pool;
    r->args = (query != NULL) ? apr_pstrdup(pool, query) : NULL;
    r->uri = apr_pstrdup(pool, "/unit-test");

    /*
     * ap_log_rerror is a macro. Before it calls the function it evaluates
     * APLOG_R_MODULE_IS_LEVEL, which reads the log level through
     * ap_get_request_logconf: r->log, then r->connection->log, then
     * r->server->log. A request_rec with none of the three set faults at the
     * call site, before any stub can run.
     *
     * Setting r->log is enough, and it takes the first branch. A zeroed
     * ap_logconf reports its own level, because ap_get_module_loglevel falls
     * back to it when module_levels is NULL.
     */
    {
        struct ap_logconf *log = apr_pcalloc(pool, sizeof(*log));
        log->level = APLOG_WARNING;
        r->log = log;
    }
    /* The defaults dims_create_config sets. */
    config->strip_metadata = 1;
    config->imagemagick_timeout = 20000;
    config->download_timeout = 10000;

    d->r = r;
    d->pool = pool;
    d->config = config;
    d->client_config = client;
    d->wand = NewMagickWand();

    snprintf(path, sizeof(path), "%s/%s", dims_stub_fixture_dir(), image);
    if (MagickReadImage(d->wand, path) == MagickFalse) {
        ExceptionType type;
        char *message = MagickGetException(d->wand, &type);

        FAIL("cannot read %s: %s", path, message ? message : "unknown");
        MagickRelinquishMemory(message);
        return NULL;
    }

    return d;
}

void
dims_fixture_free(dims_request_rec *d)
{
    if (d == NULL) {
        return;
    }
    if (d->wand != NULL) {
        DestroyMagickWand(d->wand);
        d->wand = NULL;
    }
    if (d->pool != NULL) {
        apr_pool_destroy(d->pool);
    }
}

unsigned char *
dims_fixture_export(dims_request_rec *d, size_t *length)
{
    unsigned char *blob;

    /*
     * PNG carries a tIME chunk holding the moment it was written, so two runs
     * of the same operation produce different bytes. The HTTP layer never sees
     * it: dims_process_image runs strip on every request, which removes it.
     */
    MagickSetOption(d->wand, "png:exclude-chunk", "date,time");

    /*
     * MagickThumbnailImage attaches the Thumbnail spec properties, two of
     * which describe the source file rather than the image it produced:
     * Thumb::MTime is the file's modification time, and Thumb::URI is its
     * path. git sets the modification time at checkout, so the same operation
     * on the same bytes produces a different file on every machine.
     *
     * Both are dropped here. Thumb::Image::Width and the rest describe the
     * original image and stay.
     */
    MagickDeleteImageProperty(d->wand, "Thumb::MTime");
    MagickDeleteImageProperty(d->wand, "Thumb::URI");

    MagickResetIterator(d->wand);
    blob = MagickGetImagesBlob(d->wand, length);

    if (blob == NULL) {
        FAIL("the wand produced no bytes");
    }

    return blob;
}

const char *
dims_fixture_extension(dims_request_rec *d)
{
    static char extension[16];
    char *format = MagickGetImageFormat(d->wand);
    size_t i;

    if (format == NULL) {
        return ".bin";
    }

    extension[0] = '.';
    for (i = 0; i + 2 < sizeof(extension) && format[i] != '\0'; i++) {
        extension[i + 1] = (char) tolower((unsigned char) format[i]);
    }
    extension[i + 1] = '\0';

    MagickRelinquishMemory(format);

    /* Match what the HTTP layer names a JPEG. */
    if (strcmp(extension, ".jpeg") == 0) {
        return ".jpg";
    }

    return extension;
}
