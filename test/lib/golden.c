/*
 * Copyright (c) Simple Things LLC and contributors
 * Copyright (c) 2025 Jeremy Collins (modified for go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to C for mod_dims)
 * SPDX-License-Identifier: MIT
 *
 * The full notice is in golden.h.
 */

#include "golden.h"
#include "environment.h"
#include "test.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static const char *
golden_dir(void)
{
    const char *from_env = getenv("DIMS_TEST_GOLDEN_DIR");
    return (from_env != NULL && from_env[0] != '\0') ? from_env : "/golden";
}

/* Creates the environment directory. Returns 0 on success. */
static int
ensure_dir(const char *path)
{
    if (mkdir(path, 0755) == 0 || errno == EEXIST) {
        return 0;
    }
    return 1;
}

static int
write_file(const char *path, const unsigned char *body, size_t body_len)
{
    FILE *file = fopen(path, "wb");
    size_t written;

    if (file == NULL) {
        return 1;
    }

    written = fwrite(body, 1, body_len, file);
    if (fclose(file) != 0 || written != body_len) {
        return 1;
    }

    return 0;
}

/* Reads a whole file. Sets *len and returns the bytes, or NULL. */
static unsigned char *
read_file(const char *path, size_t *len)
{
    FILE *file = fopen(path, "rb");
    unsigned char *body;
    long size;

    if (file == NULL) {
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }

    body = malloc((size_t) size + 1);
    if (body == NULL) {
        fclose(file);
        return NULL;
    }

    *len = fread(body, 1, (size_t) size, file);
    fclose(file);

    return body;
}

/* Reports the offset of the first differing byte, or -1. */
static long
first_difference(const unsigned char *a, size_t a_len, const unsigned char *b, size_t b_len)
{
    size_t shortest = (a_len < b_len) ? a_len : b_len;
    size_t i;

    for (i = 0; i < shortest; i++) {
        if (a[i] != b[i]) {
            return (long) i;
        }
    }

    return (a_len == b_len) ? -1 : (long) shortest;
}

void
assert_golden(const char *name, const unsigned char *body, size_t body_len, const char *ext)
{
    char dir[512];
    char golden_path[1024];
    char failed_path[1024];
    unsigned char *golden;
    size_t golden_len = 0;
    long offset;

    snprintf(dir, sizeof(dir), "%s/%s", golden_dir(), dims_test_environment());
    snprintf(golden_path, sizeof(golden_path), "%s/%s.golden%s", dir, name, ext);
    snprintf(failed_path, sizeof(failed_path), "%s/%s.failed%s", dir, name, ext);

    if (dims_test_updating()) {
        if (ensure_dir(dir) != 0) {
            FAIL("cannot create %s: %s", dir, strerror(errno));
            return;
        }
        if (write_file(golden_path, body, body_len) != 0) {
            FAIL("cannot write %s: %s", golden_path, strerror(errno));
            return;
        }
        dims_test_logf("wrote %s (%zu bytes)", golden_path, body_len);
        return;
    }

    golden = read_file(golden_path, &golden_len);
    if (golden == NULL) {
        FAIL("no golden file at %s. Run make test-update to create it.", golden_path);
        return;
    }

    offset = first_difference(body, body_len, golden, golden_len);
    if (offset < 0) {
        free(golden);
        return;
    }

    free(golden);

    if (ensure_dir(dir) == 0) {
        write_file(failed_path, body, body_len);
    }

    FAIL("bytes differ from %s at offset %ld. want %zu bytes, got %zu. wrote %s",
         golden_path, offset, golden_len, body_len, failed_path);
}

const char *
dims_extension_for(const char *content_type)
{
    if (content_type == NULL) {
        return ".bin";
    }
    if (strncmp(content_type, "image/png", 9) == 0) {
        return ".png";
    }
    if (strncmp(content_type, "image/jpeg", 10) == 0 ||
        strncmp(content_type, "image/jpg", 9) == 0) {
        return ".jpg";
    }
    if (strncmp(content_type, "image/gif", 9) == 0) {
        return ".gif";
    }
    if (strncmp(content_type, "image/webp", 10) == 0) {
        return ".webp";
    }
    if (strncmp(content_type, "image/tiff", 10) == 0) {
        return ".tiff";
    }
    if (strncmp(content_type, "text/plain", 10) == 0) {
        return ".txt";
    }

    return ".bin";
}
