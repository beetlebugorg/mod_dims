/*
 * Guarding an SVG source against an external reference.
 *
 * ImageMagick's SVG renderer reads a local file named by an <image> href, so
 * the module refuses an SVG that references an external resource. These cases
 * pin what the check accepts and what it refuses.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "svgguard.h"
#include "../lib/test.h"

#include <apr_general.h>
#include <string.h>

/*
 * A pool per call, destroyed after. The check creates an XML parser in the
 * pool, and destroying the pool runs the cleanup that frees it. This is the
 * request pool's lifetime, so the test frees what the server frees.
 */
static int
is_safe(const char *svg)
{
    apr_pool_t *pool;
    int result;

    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        FAIL("cannot create a pool");
        return 0;
    }

    result = dims_svg_is_safe(pool, svg, strlen(svg), NULL);
    apr_pool_destroy(pool);

    return result;
}

/* A source that is not SVG is not this check's concern. */
static void
test_non_svg_is_safe(void)
{
    static const char png[] = { (char) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0 };

    CHECK(is_safe(png), "a PNG is safe");
    CHECK(is_safe("GIF89a...."), "a GIF is safe");
    CHECK(is_safe(""), "an empty body is safe");
}

/* A self-contained SVG renders no external file. */
static void
test_self_contained_svg_is_safe(void)
{
    CHECK(is_safe("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"8\" "
                  "height=\"8\"><rect width=\"8\" height=\"8\" fill=\"red\"/>"
                  "</svg>"),
          "shapes only");
    CHECK(is_safe("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\">"
                  "<use xlink:href=\"#a\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"/>"
                  "</svg>"),
          "an internal fragment reference");
    CHECK(is_safe("<svg xmlns=\"http://www.w3.org/2000/svg\">"
                  "<image href=\"data:image/png;base64,AAAA\"/></svg>"),
          "an embedded data URI image");
}

/* An external reference is refused, whichever attribute names it. */
static void
test_external_reference_is_refused(void)
{
    CHECK(!is_safe("<svg xmlns=\"http://www.w3.org/2000/svg\" "
                   "xmlns:xlink=\"http://www.w3.org/1999/xlink\">"
                   "<image xlink:href=\"/etc/passwd\"/></svg>"),
          "xlink:href to a local path");
    CHECK(!is_safe("<svg xmlns=\"http://www.w3.org/2000/svg\">"
                   "<image href=\"/etc/passwd\"/></svg>"),
          "href to a local path");
    CHECK(!is_safe("<svg xmlns=\"http://www.w3.org/2000/svg\">"
                   "<image href=\"http://169.254.169.254/\"/></svg>"),
          "href to a URL");
    CHECK(!is_safe("<svg xmlns=\"http://www.w3.org/2000/svg\">"
                   "<image href=\"logo.png\"/></svg>"),
          "href to a relative file");
}

/* A percent or entity encoded value decodes before the check reads it. */
static void
test_encoded_reference_is_refused(void)
{
    CHECK(!is_safe("<svg xmlns=\"http://www.w3.org/2000/svg\">"
                   "<image href=\"&#x2f;etc&#x2f;passwd\"/></svg>"),
          "an entity encoded path");
}

/* An SVG that does not parse is refused rather than handed to the renderer. */
static void
test_malformed_svg_is_refused(void)
{
    CHECK(!is_safe("<svg xmlns=\"http://www.w3.org/2000/svg\"><image href="),
          "an unterminated tag");
    CHECK(!is_safe("<?xml version=\"1.0\"?><svg><rect></svg>"),
          "an unclosed element");
}

const dims_test dims_tests_unit_svgguard[] = {
    { "TestNonSvgIsSafe", test_non_svg_is_safe, NULL },
    { "TestSelfContainedSvgIsSafe", test_self_contained_svg_is_safe, NULL },
    { "TestExternalReferenceIsRefused", test_external_reference_is_refused, NULL },
    { "TestEncodedReferenceIsRefused", test_encoded_reference_is_refused, NULL },
    { "TestMalformedSvgIsRefused", test_malformed_svg_is_refused, NULL },
    DIMS_TEST_END
};
