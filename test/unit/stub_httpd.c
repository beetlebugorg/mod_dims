/*
 * The httpd and module symbols the operations reach for.
 *
 * src/mod_dims_ops.c is compiled into the test binary. It calls three things
 * that live outside itself: the httpd logger, the httpd URL unescaper, and
 * the module's own downloader. Providing them here keeps the operations
 * testable without an httpd process and without a network.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stub_httpd.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int log_enabled;

void
dims_stub_log_enable(int enabled)
{
    log_enabled = enabled;
}

/* APLOG_MARK expands to file, line, and module index. */
void
ap_log_rerror_(const char *file, int line, int module_index, int level,
               apr_status_t status, const request_rec *r, const char *fmt, ...)
{
    va_list args;

    if (!log_enabled) {
        return;
    }

    fprintf(stderr, "      [module] ");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}

/* The guard reports its configuration through this at startup. */
void
ap_log_error_(const char *file, int line, int module_index, int level,
              apr_status_t status, const server_rec *s, const char *fmt, ...)
{
    va_list args;

    if (!log_enabled) {
        return;
    }

    fprintf(stderr, "      [module] ");
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}

/*
 * httpd's unescaper, reduced to what the watermark parser needs. It decodes
 * in place and returns OK, which is what the real one does for a valid
 * string.
 */
int
ap_unescape_url(char *url)
{
    char *read = url;
    char *write = url;

    while (*read != '\0') {
        if (read[0] == '%' && isxdigit((unsigned char) read[1]) &&
            isxdigit((unsigned char) read[2])) {
            char hex[3] = { read[1], read[2], '\0' };
            *write++ = (char) strtol(hex, NULL, 16);
            read += 3;
        } else {
            *write++ = *read++;
        }
    }
    *write = '\0';

    return 0;
}

/*
 * The module's downloader, replaced by a read from the fixture directory.
 *
 * The watermark command fetches its overlay through this. Reading from disk
 * keeps the case hermetic and makes the overlay the same bytes every run.
 * The URL's last path segment names the fixture.
 */
CURLcode
dims_get_image_data(dims_request_rec *d, char *fetch_url, dims_image_data_t *data,
                    dims_allowlist_mode mode)
{
    const char *name = strrchr(fetch_url, '/');
    char path[1024];
    FILE *file;
    long size;

    data->data = NULL;
    data->size = 0;
    data->used = 0;
    data->response_code = 404;

    name = (name != NULL) ? name + 1 : fetch_url;
    snprintf(path, sizeof(path), "%s/%s", dims_stub_fixture_dir(), name);

    file = fopen(path, "rb");
    if (file == NULL) {
        return CURLE_COULDNT_CONNECT;
    }

    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return CURLE_READ_ERROR;
    }

    data->data = malloc((size_t) size);
    if (data->data == NULL) {
        fclose(file);
        return CURLE_OUT_OF_MEMORY;
    }

    data->used = fread(data->data, 1, (size_t) size, file);
    data->size = data->used;
    data->response_code = 200;
    fclose(file);

    return CURLE_OK;
}

const char *
dims_stub_fixture_dir(void)
{
    const char *from_env = getenv("DIMS_TEST_FIXTURE_DIR");
    return (from_env != NULL && from_env[0] != '\0')
               ? from_env
               : "/build/mod_dims/test/origin";
}
