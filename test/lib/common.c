/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common.h"

char *
dims_fixture_url(const char *fixture)
{
    size_t len = strlen(dims_origin_url()) + strlen(fixture) + 2;
    char *url = malloc(len);

    if (url == NULL) {
        FAIL("out of memory");
        return NULL;
    }

    snprintf(url, len, "%s/%s", dims_origin_url(), fixture);
    return url;
}

dims_response *
dims_request_ops(const char *commands, const char *fixture)
{
    char *url = dims_fixture_url(fixture);
    char *path;
    dims_response *response;

    if (url == NULL) {
        return NULL;
    }

    path = dims_sign_dims4(commands, url, NULL, NULL);
    free(url);

    if (path == NULL) {
        FAIL("signing failed for %s", commands);
        return NULL;
    }

    response = dims_get(path);
    free(path);

    return response;
}

/* "grid.png" becomes "grid". */
static void
fixture_stem(const char *fixture, char *out, size_t out_len)
{
    const char *dot = strrchr(fixture, '.');
    size_t len = (dot != NULL) ? (size_t) (dot - fixture) : strlen(fixture);

    if (len >= out_len) {
        len = out_len - 1;
    }

    memcpy(out, fixture, len);
    out[len] = '\0';
}

void
dims_run_golden(const char *name, const char *fixture, const char *commands,
                long want_width, long want_height)
{
    dims_response *response = dims_request_ops(commands, fixture);
    dims_image_size size;
    char stem[128];
    char golden_name[256];
    const char *content_type;

    if (response == NULL) {
        return;
    }

    if (response->transport_error != NULL) {
        FAIL("%s: transport failed: %s", commands, response->transport_error);
    }
    CHECK_INT(response->status, 200, commands);

    size = dims_must_size(response->body, response->body_len);
    if (want_width < 0 && want_height < 0) {
        dims_test_logf("%s: %s is %ldx%ld, %ld frame(s)", name, size.format,
                       size.width, size.height, size.frames);
    }

    if (want_width >= 0) {
        CHECK_INT(size.width, want_width, "width");
    }
    if (want_height >= 0) {
        CHECK_INT(size.height, want_height, "height");
    }

    fixture_stem(fixture, stem, sizeof(stem));
    snprintf(golden_name, sizeof(golden_name), "%s.%s", stem, name);

    content_type = dims_header_value(response, "Content-Type");
    assert_golden(golden_name, response->body, response->body_len,
                  dims_extension_for(content_type));

    dims_response_free(response);
}
