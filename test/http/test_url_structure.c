/*
 * The shape of every URL the module accepts.
 *
 * These pin where each segment sits, and what happens when one is missing,
 * empty, or extra. Nothing else in the suite asserts the layout, so a change
 * to the parsing could move a segment without a case noticing.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

#include <stdarg.h>

/* Sends a path and reports the status, with the worker still answering. */
static long
status_of(const char *path)
{
    dims_response *response = dims_get(path);
    long status;

    CHECK(response->transport_error == NULL,
          "%s: the worker must answer, not die: %s", path,
          response->transport_error ? response->transport_error : "");

    status = response->status;
    dims_response_free(response);

    return status;
}

/* Builds a path from a format, requests it, and reports the status. */
static long
status_of_f(const char *format, ...)
{
    char path[2048];
    va_list args;

    va_start(args, format);
    vsnprintf(path, sizeof(path), format, args);
    va_end(args);

    return status_of(path);
}

/*
 * /dims3/<client>/<commands>/?url=<source>
 *
 * The client id is the first segment and everything after it up to the query
 * string is the command list.
 */
static void
test_dims3_shape(void)
{
    char *url = dims_fixture_url("grid.png");
    char *encoded = dims_urlencode(url);

    CHECK_INT(status_of_f("/dims3/%s/resize/100x100/?url=%s",
                          DIMS_TEST_CLIENT, encoded), 200, "the whole shape");

    /* One command with no argument. */
    CHECK(status_of_f("/dims3/%s/strip/true/?url=%s", DIMS_TEST_CLIENT, encoded)
              == 200, "a single command");

    /* Several commands run left to right. */
    CHECK_INT(status_of_f("/dims3/%s/resize/100x100/format/png/?url=%s",
                          DIMS_TEST_CLIENT, encoded), 200, "two commands");

    free(encoded);
    free(url);
}

/* The client id has to name a configured client. */
static void
test_dims3_client_segment(void)
{
    char *url = dims_fixture_url("grid.png");
    char *encoded = dims_urlencode(url);

    CHECK(status_of_f("/dims3/NOSUCHCLIENT/resize/100x100/?url=%s", encoded)
              >= 400, "an unknown client");
    CHECK(status_of_f("/dims3//resize/100x100/?url=%s", encoded) >= 400,
          "an empty client id");
    CHECK(status_of_f("/dims3/?url=%s", encoded) >= 400, "no client id at all");

    free(encoded);
    free(url);
}

/* A request with no commands has nothing to do. */
static void
test_dims3_without_commands(void)
{
    char *url = dims_fixture_url("grid.png");
    char *encoded = dims_urlencode(url);
    long status = status_of_f("/dims3/%s/?url=%s", DIMS_TEST_CLIENT, encoded);

    dims_test_logf("/dims3/ with no commands returns %ld", status);
    CHECK(status == 200, "no commands returns the source, got %ld", status);

    free(encoded);
    free(url);
}

/* A source URL that is not there. */
static void
test_dims3_without_a_source(void)
{
    CHECK(status_of_f("/dims3/%s/resize/100x100/", DIMS_TEST_CLIENT) >= 400,
          "no url parameter and no url in the path");
    CHECK(status_of_f("/dims3/%s/resize/100x100/?url=", DIMS_TEST_CLIENT) >= 400,
          "an empty url parameter");
}

/*
 * /dims4/<client>/<signature>/<expires>/<commands>/?url=<source>
 *
 * Two segments sit between the client id and the commands. Moving either one
 * changes what the signature covers.
 */
static void
test_dims4_shape(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);

    CHECK_INT(status_of(path), 200, "the whole shape");

    free(path);
    free(url);
}

static void
test_dims4_missing_segments(void)
{
    char *url = dims_fixture_url("grid.png");
    char *encoded = dims_urlencode(url);
    char *signature = dims_signature_dims4(DIMS_TEST_EXPIRES, DIMS_TEST_SECRET,
                                           "resize/100x100/", url, NULL, 0);

    /* No expiry: the commands slide into its place. */
    CHECK(status_of_f("/dims4/%s/%s/resize/100x100/?url=%s",
                      DIMS_TEST_CLIENT, signature, encoded) >= 400,
          "no expiry segment");

    /* No signature: the expiry slides into its place. */
    CHECK(status_of_f("/dims4/%s/%s/resize/100x100/?url=%s",
                      DIMS_TEST_CLIENT, DIMS_TEST_EXPIRES, encoded) >= 400,
          "no signature segment");

    /* Neither. */
    CHECK(status_of_f("/dims4/%s/resize/100x100/?url=%s",
                      DIMS_TEST_CLIENT, encoded) >= 400,
          "neither segment");

    free(signature);
    free(encoded);
    free(url);
}

/* The expiry is a number of seconds, and the past is refused. */
static void
test_dims4_expiry_segment(void)
{
    char *url = dims_fixture_url("grid.png");
    char *encoded = dims_urlencode(url);
    char *signature = dims_signature_dims4("1", DIMS_TEST_SECRET,
                                           "resize/100x100/", url, NULL, 0);

    CHECK(status_of_f("/dims4/%s/%s/1/resize/100x100/?url=%s",
                      DIMS_TEST_CLIENT, signature, encoded) >= 400,
          "an expiry in the past");

    free(signature);
    CHECK(status_of_f("/dims4/%s/aaaaaa/notanumber/resize/100x100/?url=%s",
                      DIMS_TEST_CLIENT, encoded) >= 400,
          "an expiry that is not a number");

    free(encoded);
    free(url);
}

/*
 * The source may sit in the path instead of the query string. httpd collapses
 * the double slash, so it arrives with one.
 */
static void
test_source_in_the_path(void)
{
    dims_response *response;
    char path[1024];

    snprintf(path, sizeof(path), "/dims3/%s/resize/100x100/http:/origin:8080/grid.png",
             DIMS_TEST_CLIENT);
    response = dims_get(path);

    CHECK(response->transport_error == NULL, "the worker must answer: %s",
          response->transport_error ? response->transport_error : "");
    dims_test_logf("a source in the path returns %ld", response->status);
    CHECK_INT(response->status, 200, "a source in the path");

    dims_response_free(response);
}

/* A trailing slash on the command list, and none. */
static void
test_trailing_slash(void)
{
    char *url = dims_fixture_url("grid.png");
    char *encoded = dims_urlencode(url);

    CHECK_INT(status_of_f("/dims3/%s/resize/100x100/?url=%s",
                          DIMS_TEST_CLIENT, encoded), 200, "with a trailing slash");
    CHECK_INT(status_of_f("/dims3/%s/resize/100x100?url=%s",
                          DIMS_TEST_CLIENT, encoded), 200, "without one");

    free(encoded);
    free(url);
}

/*
 * /dims/<client>/<bitmap>/<width>/<height>/<quality>/<source>
 *
 * The legacy endpoint translates five numbers into a command list. The bitmap
 * names the operations: 1 resize, 2 reformat, 4 crop, 8 sharpen, then 256 jpg,
 * 512 gif, 1024 png.
 */
static void
test_legacy_shape(void)
{
    long status = status_of_f("/dims/%s/1/100/100/70/http:/origin:8080/grid.png",
                              DIMS_TEST_CLIENT);

    dims_test_logf("the legacy endpoint returns %ld", status);
    CHECK_INT(status, 200, "resize to 100x100 at quality 70");
}

/*
 * The five numbers are read with one sscanf and no validation after it, so a
 * short list slides the source URL into the last number's place and the
 * request still succeeds. These record what happens, not what should.
 */
static void
test_legacy_missing_segments(void)
{
    dims_response *response;
    dims_image_size size;
    char path[512];

    snprintf(path, sizeof(path), "/dims/%s/1/100/100/http:/origin:8080/grid.png",
             DIMS_TEST_CLIENT);
    response = dims_get(path);

    CHECK_INT(response->status, 200, "four numbers where five are expected");
    size = dims_must_size(response->body, response->body_len);
    dims_test_logf("the scheme became the quality, and the image came back %ldx%ld",
                   size.width, size.height);
    CHECK_INT(size.width, 100, "the resize still ran");
    dims_response_free(response);

    CHECK(status_of_f("/dims/%s/http:/origin:8080/grid.png", DIMS_TEST_CLIENT)
              >= 400, "no numbers at all");
    CHECK(status_of("/dims/") >= 400, "nothing but the prefix");
}

/*
 * The bitmap is read with atoi, which answers 0 for anything that is not a
 * number, and 0 names no operation. The source then passes through at its
 * original size.
 */
static void
test_legacy_bitmap(void)
{
    dims_response *response;
    dims_image_size size;
    char path[512];

    snprintf(path, sizeof(path), "/dims/%s/x/100/100/70/http:/origin:8080/grid.png",
             DIMS_TEST_CLIENT);
    response = dims_get(path);

    CHECK_INT(response->status, 200, "a bitmap that is not a number");
    size = dims_must_size(response->body, response->body_len);
    CHECK_INT(size.width, 512, "the source passes through at its own size");
    dims_response_free(response);

    CHECK(status_of_f("/dims/%s/1/0/0/70/http:/origin:8080/grid.png",
                      DIMS_TEST_CLIENT) >= 400, "a resize to no size");
}

/* The status endpoint takes no segments. */
static void
test_status_shape(void)
{
    CHECK_INT(status_of("/dims-status/"), 200, "the status endpoint");
}

const dims_test dims_tests_url_structure[] = {
    { "TestDims3Shape", test_dims3_shape, NULL },
    { "TestDims3ClientSegment", test_dims3_client_segment, NULL },
    { "TestDims3WithoutCommands", test_dims3_without_commands, NULL },
    { "TestDims3WithoutASource", test_dims3_without_a_source, NULL },
    { "TestDims4Shape", test_dims4_shape, NULL },
    { "TestDims4MissingSegments", test_dims4_missing_segments, NULL },
    { "TestDims4ExpirySegment", test_dims4_expiry_segment, NULL },
    { "TestSourceInThePath", test_source_in_the_path, NULL },
    { "TestTrailingSlash", test_trailing_slash, NULL },
    { "TestLegacyShape", test_legacy_shape, NULL },
    { "TestLegacyMissingSegments", test_legacy_missing_segments, NULL },
    { "TestLegacyBitmap", test_legacy_bitmap, NULL },
    { "TestStatusShape", test_status_shape, NULL },
    DIMS_TEST_END
};
