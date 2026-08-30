/*
 * The status a failure reports when there is no error image to send.
 *
 * Every client on the main test server has an error image, through
 * DimsDefaultImageURL, so a failure there answers with a picture and the
 * status comes from the response writer. The server on port 8001 does not
 * have one,
 * which is the only way to reach the other status path.
 *
 * That path answered 404 for every failure until the two mappings were made
 * to agree. A 404 tells a caller the image is missing, which was wrong for a
 * bad signature, an unknown application id, and a timeout alike.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

/* The second server, configured with no error image. */
static const char *
no_error_image_url(void)
{
    const char *from_env = getenv("DIMS_TEST_NO_ERROR_IMAGE_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8001";
}

static long
status_of(const char *path)
{
    char url[2048];
    dims_response *response;
    long status;

    snprintf(url, sizeof(url), "%s%s", no_error_image_url(), path);
    response = dims_get_absolute(url);
    status = response->status;

    CHECK(response->transport_error == NULL, "%s: %s", path,
          response->transport_error ? response->transport_error : "");

    dims_response_free(response);
    return status;
}

static void
test_unknown_client_is_a_server_error(void)
{
    CHECK_INT(status_of("/dims3/NOSUCH/resize/100x100/?url=x"), 500,
              "an unknown application id");
}

static void
test_wrong_signature_is_a_bad_request(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4_with("ffffff", DIMS_TEST_EXPIRES, "resize/100x100",
                                      url, NULL, NULL);

    CHECK_INT(status_of(path), 400, "a wrong signature");

    free(path);
    free(url);
}

static void
test_expired_signature_is_a_bad_request(void)
{
    char *url = dims_fixture_url("grid.png");
    char *signature = dims_signature_dims4("1000000000", DIMS_TEST_SECRET,
                                           "resize/100x100/", url, NULL, 0);
    char *path = dims_sign_dims4_with(signature, "1000000000", "resize/100x100",
                                      url, NULL, NULL);

    CHECK_INT(status_of(path), 400, "an expired signature");

    free(path);
    free(signature);
    free(url);
}

/*
 * A source that is genuinely missing is the one case 404 was right for.
 *
 * This kills the worker instead. When the source fetch fails,
 * dims_handle_request asks for the error image, and dims_fetch_remote_image
 * takes d->no_image_url when it is given no URL. With no error image that
 * pointer is NULL, and the file:/// check reads it before anything tests it:
 *
 *     char *fetch_url = url ? (char *) url : d->no_image_url;
 *     if (url == NULL && strncmp(fetch_url, "file:///", 8) == 0)
 *
 * Only reachable with no error image configured, which is why it has gone
 * unseen: DimsDefaultImageURL is usually set, and setting it hides this.
 */
static void
test_missing_source_is_not_found(void)
{
    char *url = dims_fixture_url("missing.png");
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);

    CHECK_INT(status_of(path), 404, "a source that returns 404");

    free(path);
    free(url);
}


/*
 * An origin that fails with anything other than 404.
 *
 * dims_fetch_remote_image only records a status for a 404, so this request
 * reaches the end still marked successful. Asking dims_cleanup to keep that
 * status answers 200 with no body, which is worse than the 404 this used to
 * give: a caller and every cache in front of it would store an empty success.
 */
static void
test_origin_failure_is_not_success(void)
{
    char *url = dims_fixture_url("broken.png");
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);
    long status = status_of(path);

    dims_test_logf("an origin 500 returns %ld", status);
    CHECK(status >= 400, "an origin failure must not answer success, got %ld", status);

    free(path);
    free(url);
}

/*
 * A failure the module decided itself, on a request whose source fetch worked.
 *
 * The fetch leaves 200 on the request, so a mapping that read the origin's
 * status here would answer 200 with no body. The module's own status is the
 * one that describes what happened. 500 is not the clearest answer for a
 * malformed geometry, but it is the answer the module gives, and this case
 * holds it still while the mapping around it moves.
 */
static void
test_bad_geometry_reports_the_module_status(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path = dims_sign_dims4("resize/not-a-size", url, NULL, NULL);
    long status = status_of(path);

    dims_test_logf("a malformed geometry with no error image returns %ld", status);
    CHECK_INT(status, 500, "a malformed geometry");

    free(path);
    free(url);
}

/* With no error image the module's own status reaches the client. */
static void
test_quality_out_of_range_is_a_bad_request(void)
{
    char *url = dims_fixture_url("pexels-photo-1539116.jpeg");
    char *path = dims_sign_dims4("quality/500", url, NULL, NULL);

    CHECK_INT(status_of(path), 400, "quality/500");

    free(path);
    free(url);
}

/* A watermark needs three arguments. */
static void
test_watermark_short_argument_list_is_a_bad_request(void)
{
    char *url = dims_fixture_url("grid.png");
    char *overlay = dims_fixture_url("overlay.png");
    char *encoded = dims_urlencode(overlay);
    char extra[1024];
    char *path;

    snprintf(extra, sizeof(extra), "overlay=%s", encoded);
    path = dims_sign_dims4("watermark/0.2", url, extra, "overlay");

    CHECK_INT(status_of(path), 400, "watermark with one argument");

    free(path);
    free(encoded);
    free(overlay);
    free(url);
}

/*
 * A crop region entirely off the image, and one whose offset is exactly the
 * width. Both leave nothing to cut out. go-dims refuses the first pair, and
 * the second used to answer 500 while the offsets on either side of it were
 * accepted.
 */
static void
test_crop_outside_the_image_is_a_bad_request(void)
{
    char *url = dims_fixture_url("grid.png");
    char *path;

    path = dims_sign_dims4("crop/256x256+768+768", url, NULL, NULL);
    CHECK_INT(status_of(path), 400, "an x offset past the image");
    free(path);

    path = dims_sign_dims4("crop/256x256+0+768", url, NULL, NULL);
    CHECK_INT(status_of(path), 400, "a y offset past the image");
    free(path);

    path = dims_sign_dims4("crop/50x50+512+0", url, NULL, NULL);
    CHECK_INT(status_of(path), 400, "an x offset of exactly the width");
    free(path);

    /* One column remains, so this one is a crop rather than a refusal. */
    path = dims_sign_dims4("crop/50x50+511+0", url, NULL, NULL);
    CHECK_INT(status_of(path), 200, "one pixel inside the edge");
    free(path);

    free(url);
}

const dims_test dims_tests_no_error_image[] = {
    { "TestUnknownClientIsAServerError", test_unknown_client_is_a_server_error, NULL },
    { "TestWrongSignatureIsABadRequest", test_wrong_signature_is_a_bad_request, NULL },
    { "TestExpiredSignatureIsABadRequest", test_expired_signature_is_a_bad_request, NULL },
    { "TestMissingSourceIsNotFound", test_missing_source_is_not_found, NULL },
    { "TestOriginFailureIsNotSuccess", test_origin_failure_is_not_success, NULL },
    { "TestQualityOutOfRangeIsABadRequest",
      test_quality_out_of_range_is_a_bad_request, NULL },
    { "TestWatermarkShortArgumentListIsABadRequest",
      test_watermark_short_argument_list_is_a_bad_request, NULL },
    { "TestCropOutsideTheImageIsABadRequest",
      test_crop_outside_the_image_is_a_bad_request, NULL },
    { "TestBadGeometryReportsTheModuleStatus",
      test_bad_geometry_reports_the_module_status, NULL },
    DIMS_TEST_END
};
