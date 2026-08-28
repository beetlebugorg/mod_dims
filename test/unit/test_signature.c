/*
 * The /dims5/ signature.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "signature.h"
#include "../lib/test.h"

#include <apr_general.h>
#include <apr_strings.h>
#include <string.h>

static apr_pool_t *
sig_pool(void)
{
    static apr_pool_t *pool;

    if (pool == NULL && apr_pool_create(&pool, NULL) != APR_SUCCESS) {
        FAIL("cannot create a pool");
    }

    return pool;
}

static void
check_escape(const char *in, const char *want)
{
    const char *got = dims_query_escape(sig_pool(), in);

    CHECK(strcmp(got, want) == 0, "escape(%s): want %s, got %s", in, want, got);
}

/*
 * Everything outside A-Za-z0-9-_.~ is escaped, a space becomes a plus, and the
 * hex is uppercase. Another encoder would produce a different signature for
 * the same request.
 */
static void
test_query_escape(void)
{
    check_escape("abcXYZ019", "abcXYZ019");
    check_escape("-_.~", "-_.~");
    check_escape(" ", "+");
    check_escape("a b", "a+b");
    check_escape("/", "%2F");
    check_escape(":", "%3A");
    check_escape("&", "%26");
    check_escape("=", "%3D");
    check_escape("+", "%2B");
    check_escape("%", "%25");
    check_escape("https://example.com/a.jpg",
                 "https%3A%2F%2Fexample.com%2Fa.jpg");
    check_escape("", "");
    check_escape(NULL, "");
}

static void
check_query(const char *in, const char *want)
{
    const char *got = dims_signed_query(sig_pool(), in);

    CHECK(strcmp(got, want) == 0, "query(%s): want [%s], got [%s]", in, want, got);
}

/* Ordered by name, whatever order the query gave. */
static void
test_signed_query_orders_by_name(void)
{
    check_query("b=2&a=1&c=3", "a=1&b=2&c=3");
    check_query("c=3&b=2&a=1", "a=1&b=2&c=3");
    check_query("a=1", "a=1");
    check_query("", "");
    check_query(NULL, "");
}

/* sig, url, eurl, _keys, and download take no part. */
static void
test_signed_query_drops_the_unsigned(void)
{
    check_query("sig=abc&a=1", "a=1");
    check_query("url=http://x/y.jpg&a=1", "a=1");
    check_query("eurl=AAAA&a=1", "a=1");
    check_query("_keys=overlay&a=1", "a=1");
    check_query("download=1&a=1", "a=1");
    check_query("sig=a&url=b&eurl=c&_keys=d&download=e", "");
}

/*
 * The name is part of the string, so moving a character from one parameter to
 * the next changes the result. The values alone would not: "ab" then "c" reads
 * the same as "a" then "bc".
 */
static void
test_signed_query_covers_the_names(void)
{
    const char *first = dims_signed_query(sig_pool(), "a=ab&b=c");
    const char *second = dims_signed_query(sig_pool(), "a=a&b=bc");

    CHECK(strcmp(first, second) != 0,
          "a=ab&b=c and a=a&b=bc must differ: [%s] and [%s]", first, second);
}

/* A value holding a separator is encoded, so it cannot pose as two. */
static void
test_signed_query_encodes_a_separator(void)
{
    check_query("a=1%26b%3D2", "a=1%26b%3D2");
    check_query("a=x y", "a=x+y");
}

/* A parameter with several values keeps the order the query gave. */
static void
test_signed_query_keeps_repeated_values(void)
{
    check_query("a=2&a=1", "a=2&a=1");
    check_query("b=1&a=2&a=1", "a=2&a=1&b=1");
}

/* A parameter with no value contributes an empty one. */
static void
test_signed_query_handles_a_valueless_parameter(void)
{
    check_query("a&b=1", "a=&b=1");
    check_query("a=", "a=");
}

/* One field per line, in a fixed order. */
static void
test_message(void)
{
    const char *got = dims_signature_message(sig_pool(), "resize/100x100/",
                                             "https://example.com/a.jpg", "a=1");

    CHECK(strcmp(got, "resize/100x100/\nhttps://example.com/a.jpg\na=1") == 0,
          "the message: [%s]", got);
}

/* A known vector, so a change to the construction is visible. */
static void
test_compute(void)
{
    const char *got = dims_signature_compute(sig_pool(), "secret", "message");

    CHECK(got != NULL && strlen(got) == DIMS_SIGNATURE_LENGTH,
          "a full length digest, got %s", got ? got : "(null)");
    CHECK(got != NULL &&
              strcmp(got, "8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b") == 0,
          "hmac-sha256(secret, message): %s", got ? got : "(null)");
}

static void
test_equal(void)
{
    const char *a = dims_signature_compute(sig_pool(), "k", "m");
    const char *b = dims_signature_compute(sig_pool(), "k", "m");
    char *wrong = apr_pstrdup(sig_pool(), a);

    CHECK(dims_signature_equal(a, b), "the same digest");

    wrong[DIMS_SIGNATURE_LENGTH - 1] ^= 1;
    CHECK(!dims_signature_equal(a, wrong), "a digest differing in the last byte");

    CHECK(!dims_signature_equal(a, "short"), "a short value");
    CHECK(!dims_signature_equal(a, NULL), "no value");
    CHECK(!dims_signature_equal(NULL, NULL), "neither value");
}

/* A line break in a signed field could stand in for two fields. */
static void
test_field_ok(void)
{
    CHECK(dims_signature_field_ok("resize/100x100/"), "an ordinary field");
    CHECK(dims_signature_field_ok(NULL), "no field");
    CHECK(!dims_signature_field_ok("a\nb"), "a line feed");
    CHECK(!dims_signature_field_ok("a\rb"), "a carriage return");
    CHECK(!dims_signature_field_ok("a\tb"), "a tab");
    CHECK(!dims_signature_field_ok("a\x7f" "b"), "a delete");
}

const dims_test dims_tests_unit_signature[] = {
    { "TestQueryEscape", test_query_escape, NULL },
    { "TestSignedQueryOrdersByName", test_signed_query_orders_by_name, NULL },
    { "TestSignedQueryDropsTheUnsigned", test_signed_query_drops_the_unsigned, NULL },
    { "TestSignedQueryCoversTheNames", test_signed_query_covers_the_names, NULL },
    { "TestSignedQueryEncodesASeparator", test_signed_query_encodes_a_separator, NULL },
    { "TestSignedQueryKeepsRepeatedValues",
      test_signed_query_keeps_repeated_values, NULL },
    { "TestSignedQueryHandlesAValuelessParameter",
      test_signed_query_handles_a_valueless_parameter, NULL },
    { "TestMessage", test_message, NULL },
    { "TestCompute", test_compute, NULL },
    { "TestEqual", test_equal, NULL },
    { "TestFieldOk", test_field_ok, NULL },
    DIMS_TEST_END
};
