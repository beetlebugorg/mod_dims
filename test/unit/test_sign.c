/*
 * The signing library.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dims_sign.h>

#include "../lib/test.h"

#include <stdlib.h>
#include <string.h>

#define TEST_KEY "0123456789abcdef0123456789abcdef"
#define TEST_SECRET "t3stk3y"
#define TEST_IMAGE "http%3A%2F%2Forigin%3A8080%2Fgrid.png"

/* A value no function writes, so an untouched out parameter is visible. */
static char *const untouched = (char *) (void *) &untouched;

static void
check_escape(const char *in, const char *want)
{
    char *got = NULL;

    CHECK_INT(dims_sign_escape(in, &got), DIMS_SIGN_OK, "escape");
    CHECK_STR(got, want, "escape");
    dims_sign_free(got);
}

/*
 * Everything outside A-Za-z0-9-_.~ is escaped, a space becomes a plus, and the
 * hex is uppercase. Another encoder would produce a different signature for
 * the same request.
 */
static void
test_escape(void)
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
    check_escape("*", "%2A");
    check_escape("https://example.com/a.jpg",
                 "https%3A%2F%2Fexample.com%2Fa.jpg");
    check_escape("", "");
    check_escape(NULL, "");
}

static void
check_query(const char *in, const char *want)
{
    char *got = NULL;

    CHECK_INT(dims_sign_canonical_query(in, &got), DIMS_SIGN_OK, "query");
    CHECK_STR(got, want, "query");
    dims_sign_free(got);
}

/* Ordered by the bytes of the name, whatever order the query gave. */
static void
test_canonical_query_orders_by_name(void)
{
    check_query("b=2&a=1&c=3", "a=1&b=2&c=3");
    check_query("c=3&b=2&a=1", "a=1&b=2&c=3");
    check_query("a=1", "a=1");
    check_query("", "");
    check_query(NULL, "");

    /* A hyphen is 0x2D and sorts before every letter. */
    check_query("ab=2&a-b=1", "a-b=1&ab=2");

    /* An upper case letter sorts before a lower case one. */
    check_query("a=1&Z=2", "Z=2&a=1");
}

/* sig, url, eurl, _keys, and download take no part. */
static void
test_canonical_query_drops_the_unsigned(void)
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
test_canonical_query_covers_the_names(void)
{
    char *first = NULL;
    char *second = NULL;

    CHECK_INT(dims_sign_canonical_query("a=ab&b=c", &first), DIMS_SIGN_OK, "first");
    CHECK_INT(dims_sign_canonical_query("a=a&b=bc", &second), DIMS_SIGN_OK, "second");

    CHECK(strcmp(first, second) != 0,
          "a=ab&b=c and a=a&b=bc must differ: [%s] and [%s]", first, second);

    dims_sign_free(first);
    dims_sign_free(second);
}

/* A value holding a separator is encoded, so it cannot pose as two. */
static void
test_canonical_query_encodes_a_separator(void)
{
    check_query("a=1%26b%3D2", "a=1%26b%3D2");
    check_query("a=x y", "a=x+y");
    check_query("a=x+y", "a=x+y");
}

/* A name that appears more than once keeps the order the query gave. */
static void
test_canonical_query_keeps_repeated_values(void)
{
    check_query("a=2&a=1", "a=2&a=1");
    check_query("b=1&a=2&a=1", "a=2&a=1&b=1");
}

/* A parameter with no equals sign has an empty value. */
static void
test_canonical_query_handles_a_valueless_parameter(void)
{
    check_query("a&b=1", "a=&b=1");
    check_query("a=", "a=");
}

/* A known vector, so a change to the construction is visible. */
static void
test_dims5_digest(void)
{
    char digest[DIMS_SIGN_DIMS5_LENGTH + 1];

    CHECK_INT(dims_sign_dims5_digest(TEST_KEY, "resize/100x100/",
                                     "http://origin:8080/grid.png", "", digest),
              DIMS_SIGN_OK, "digest");
    CHECK_STR(digest,
              "e9d70afb0b29520bae7fa47fb3de2d4c62c85f40d89636f6b190ac8055838bff",
              "the /dims5/ digest");

    CHECK_INT(dims_sign_dims5_digest(TEST_KEY, "resize/100x100/",
                                     "http://origin:8080/grid.png", "tag=b&tag=a",
                                     digest),
              DIMS_SIGN_OK, "digest with a query");
    CHECK_STR(digest,
              "146f18539b8f82768fe271f202b532961db33f8dcffbe3b8646a7ed0d85354e0",
              "the /dims5/ digest with a query");

    CHECK_INT(dims_sign_dims5_digest(NULL, "a", "b", "", digest),
              DIMS_SIGN_BAD_ARGUMENT, "no key");
    CHECK_INT(dims_sign_dims5_digest("", "a", "b", "", digest),
              DIMS_SIGN_BAD_ARGUMENT, "an empty key");
}

/* One field per line, in a fixed order. */
static void
test_dims5_message(void)
{
    char *got = NULL;

    CHECK_INT(dims_sign_dims5_message(
                      "/dims5/resize/100x100/?" "url=" TEST_IMAGE "&tag=b&tag=a",
                      NULL, &got),
              DIMS_SIGN_OK, "the message");
    CHECK_STR(got,
              "resize/100x100/\nhttp://origin:8080/grid.png\ntag=b&tag=a",
              "the message");
    dims_sign_free(got);
}

static void
test_dims5_equal(void)
{
    char a[DIMS_SIGN_DIMS5_LENGTH + 1];
    char b[DIMS_SIGN_DIMS5_LENGTH + 1];

    CHECK_INT(dims_sign_dims5_digest("k", "m", "n", "", a), DIMS_SIGN_OK, "a");
    CHECK_INT(dims_sign_dims5_digest("k", "m", "n", "", b), DIMS_SIGN_OK, "b");

    CHECK(dims_sign_dims5_equal(a, b), "the same digest");

    b[DIMS_SIGN_DIMS5_LENGTH - 1] ^= 1;
    CHECK(!dims_sign_dims5_equal(a, b), "a digest differing in the last byte");

    CHECK(!dims_sign_dims5_equal(a, "short"), "a short value");
    CHECK(!dims_sign_dims5_equal(a, NULL), "no value");
    CHECK(!dims_sign_dims5_equal(NULL, NULL), "neither value");
}

/* A known vector, and the _keys contract the module follows. */
static void
test_dims4_digest(void)
{
    char digest[DIMS_SIGN_DIMS4_DIGEST + 1];
    dims_sign_param keys[3];

    CHECK_INT(dims_sign_dims4_digest(TEST_SECRET, "2147483647", "resize/100x100/",
                                     "http://origin:8080/grid.png", NULL, 0,
                                     digest),
              DIMS_SIGN_OK, "digest");
    CHECK_STR(digest, "82ea1ce80bea7fd48834e7b7dbab69e1", "the /dims4/ digest");

    /* The values are concatenated with no separator. */
    keys[0].name = "a";
    keys[0].value = "a";
    keys[1].name = "b";
    keys[1].value = "b";

    CHECK_INT(dims_sign_dims4_digest(TEST_SECRET, "2147483647", "resize/100x100/",
                                     "http://origin:8080/grid.png", keys, 2,
                                     digest),
              DIMS_SIGN_OK, "digest with keys");
    CHECK_STR(digest, "7804fe161fc78d0f401540e8526850ca",
              "the /dims4/ digest with two keyed values");

    /* A NULL value contributes nothing. */
    keys[0].name = "a";
    keys[0].value = "a";
    keys[1].name = "absent";
    keys[1].value = NULL;
    keys[2].name = "b";
    keys[2].value = "b";

    CHECK_INT(dims_sign_dims4_digest(TEST_SECRET, "2147483647", "resize/100x100/",
                                     "http://origin:8080/grid.png", keys, 3,
                                     digest),
              DIMS_SIGN_OK, "digest with an absent key");
    CHECK_STR(digest, "7804fe161fc78d0f401540e8526850ca",
              "a NULL value leaves the digest unchanged");
}

/* The module compares six characters without regard to case. */
static void
test_dims4_equal(void)
{
    const char *expected = "82ea1ce80bea7fd48834e7b7dbab69e1";

    CHECK(dims_sign_dims4_equal(expected, "82ea1c"), "the first six");
    CHECK(dims_sign_dims4_equal(expected, "82EA1C"), "upper case");
    CHECK(dims_sign_dims4_equal(expected, expected), "the whole digest");
    CHECK(!dims_sign_dims4_equal(expected, "82ea1d"), "a different sixth");
    CHECK(!dims_sign_dims4_equal(expected, "82ea1"), "five characters");
    CHECK(!dims_sign_dims4_equal(expected, NULL), "no value");
}

/* A line break in a signed field could stand in for two fields. */
static void
test_field_ok(void)
{
    CHECK(dims_sign_field_ok("resize/100x100/"), "an ordinary field");
    CHECK(dims_sign_field_ok(NULL), "no field");
    CHECK(!dims_sign_field_ok("a\nb"), "a line feed");
    CHECK(!dims_sign_field_ok("a\rb"), "a carriage return");
    CHECK(!dims_sign_field_ok("a\tb"), "a tab");
    CHECK(!dims_sign_field_ok("a\x7f" "b"), "a delete");
}

static void
check_dims5_url(const char *in, const char *prefix, const char *want)
{
    char *got = NULL;

    CHECK_INT(dims_sign_dims5_url(in, TEST_KEY, prefix, &got), DIMS_SIGN_OK,
              "sign");
    CHECK_STR(got, want, in);
    dims_sign_free(got);
}

/* The query passes through, and sig goes on the end. */
static void
test_dims5_url(void)
{
    const char *digest =
        "e9d70afb0b29520bae7fa47fb3de2d4c62c85f40d89636f6b190ac8055838bff";

    check_dims5_url("/dims5/resize/100x100/?url=" TEST_IMAGE, NULL,
                    "/dims5/resize/100x100/?url=" TEST_IMAGE "&sig=e9d70afb0b295"
                    "20bae7fa47fb3de2d4c62c85f40d89636f6b190ac8055838bff");

    /* An empty prefix means the conventional one. */
    check_dims5_url("/dims5/resize/100x100/?url=" TEST_IMAGE, "",
                    "/dims5/resize/100x100/?url=" TEST_IMAGE "&sig=e9d70afb0b295"
                    "20bae7fa47fb3de2d4c62c85f40d89636f6b190ac8055838bff");

    /* A rewrite in front of the module signs the same commands. */
    check_dims5_url("https://cdn.example.com/img/resize/100x100/?url=" TEST_IMAGE,
                    "/img/",
                    "https://cdn.example.com/img/resize/100x100/?url=" TEST_IMAGE
                    "&sig=e9d70afb0b29520bae7fa47fb3de2d4c62c85f40d89636f6b190ac"
                    "8055838bff");

    /* An input that already holds a sig gets a new one in its place. */
    check_dims5_url("/dims5/resize/100x100/?url=" TEST_IMAGE "&sig=deadbeef",
                    NULL,
                    "/dims5/resize/100x100/?url=" TEST_IMAGE "&sig=e9d70afb0b295"
                    "20bae7fa47fb3de2d4c62c85f40d89636f6b190ac8055838bff");

    CHECK(strlen(digest) == DIMS_SIGN_DIMS5_LENGTH, "a full length signature");
}

/* The path is rebuilt from its four segments. */
static void
test_dims4_url(void)
{
    char *got = NULL;

    CHECK_INT(dims_sign_dims4_url(
                      "/dims4/TEST/xxxxxx/2147483647/resize/100x100/?url="
                      TEST_IMAGE, TEST_SECRET, NULL, &got),
              DIMS_SIGN_OK, "sign");
    CHECK_STR(got, "/dims4/TEST/82ea1c/2147483647/resize/100x100/?url="
              TEST_IMAGE, "the signed path");
    dims_sign_free(got);

    /* A placeholder equal to the client id still works. */
    CHECK_INT(dims_sign_dims4_url(
                      "/dims4/TEST/2147483647/2147483647/resize/100x100/?url="
                      TEST_IMAGE, TEST_SECRET, NULL, &got),
              DIMS_SIGN_OK, "a placeholder equal to the expiry");
    CHECK_STR(got, "/dims4/TEST/82ea1ce80b/2147483647/resize/100x100/?url="
              TEST_IMAGE, "ten characters in, ten characters out");
    dims_sign_free(got);

    /* The placeholder sets the length, up to the whole digest. */
    CHECK_INT(dims_sign_dims4_url(
                      "/dims4/TEST/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/2147483647/"
                      "resize/100x100/?url=" TEST_IMAGE, TEST_SECRET, NULL, &got),
              DIMS_SIGN_OK, "a thirty two character placeholder");
    CHECK_STR(got, "/dims4/TEST/82ea1ce80bea7fd48834e7b7dbab69e1/2147483647/"
              "resize/100x100/?url=" TEST_IMAGE, "the whole digest");
    dims_sign_free(got);
}

static void
check_refused(dims_sign_status want, dims_sign_status got, const char *what)
{
    CHECK_INT(got, want, what);
}

/* One case for each clause the header names. */
static void
test_refuses_a_bad_url(void)
{
    char *out = untouched;

    check_refused(DIMS_SIGN_BAD_URL,
                  dims_sign_dims5_url("/other/resize/1x1/?url=" TEST_IMAGE,
                                      TEST_KEY, NULL, &out),
                  "a path outside the prefix");

    check_refused(DIMS_SIGN_BAD_URL,
                  dims_sign_dims5_url("/dims5/crop/%zz/?url=" TEST_IMAGE,
                                      TEST_KEY, NULL, &out),
                  "a percent escape that is not two hex digits");

    check_refused(DIMS_SIGN_BAD_URL,
                  dims_sign_dims5_url("/dims5/resize/1x1/?tag=a", TEST_KEY,
                                      NULL, &out),
                  "a query with no url");

    check_refused(DIMS_SIGN_BAD_URL,
                  dims_sign_dims5_url("/dims5/resize/1x1/", TEST_KEY, NULL, &out),
                  "no query at all");

    check_refused(DIMS_SIGN_BAD_FIELD,
                  dims_sign_dims5_url("/dims5/crop/%0A/?url=" TEST_IMAGE,
                                      TEST_KEY, NULL, &out),
                  "a control character in the commands");

    check_refused(DIMS_SIGN_BAD_URL,
                  dims_sign_dims4_url("/dims4/TEST/xxxxxx/2147483647?url="
                                      TEST_IMAGE, TEST_SECRET, NULL, &out),
                  "three segments after the prefix");

    check_refused(DIMS_SIGN_BAD_URL,
                  dims_sign_dims4_url("/dims4/TEST/xxxxxx/soon/resize/1x1/?url="
                                      TEST_IMAGE, TEST_SECRET, NULL, &out),
                  "an expiry that is not decimal digits");

    check_refused(DIMS_SIGN_BAD_URL,
                  dims_sign_dims4_url("/dims4/TEST/xxx/2147483647/resize/1x1/"
                                      "?url=" TEST_IMAGE, TEST_SECRET, NULL,
                                      &out),
                  "a placeholder under six characters");

    check_refused(DIMS_SIGN_BAD_URL,
                  dims_sign_dims4_url("/dims4/TEST/xxxxxx/2147483647/resize/1x1/"
                                      "?tag=a", TEST_SECRET, NULL, &out),
                  "a /dims4/ query with no url");

    check_refused(DIMS_SIGN_BAD_ARGUMENT,
                  dims_sign_dims5_url("/dims5/resize/1x1/?url=" TEST_IMAGE, "",
                                      NULL, &out),
                  "an empty key");

    check_refused(DIMS_SIGN_BAD_ARGUMENT,
                  dims_sign_dims4_url("/dims4/TEST/xxxxxx/2147483647/resize/1x1/"
                                      "?url=" TEST_IMAGE, NULL, NULL, &out),
                  "no secret");

    CHECK(out == untouched, "a failure leaves the out parameter untouched");
}

/* dims_sign_free releases what the library wrote, and accepts NULL. */
static void
test_allocation_contract(void)
{
    char *out = NULL;

    dims_sign_free(NULL);

    CHECK_INT(dims_sign_escape("", &out), DIMS_SIGN_OK, "an empty value");
    CHECK(out != NULL, "an empty result is still a string");
    CHECK_STR(out, "", "an empty result");
    dims_sign_free(out);

    out = NULL;
    CHECK_INT(dims_sign_canonical_query("", &out), DIMS_SIGN_OK, "an empty query");
    CHECK(out != NULL, "an empty canonical query is still a string");
    dims_sign_free(out);

    CHECK_INT(dims_sign_escape("a", NULL), DIMS_SIGN_BAD_ARGUMENT, "no out");
    CHECK_INT(dims_sign_canonical_query("a=1", NULL), DIMS_SIGN_BAD_ARGUMENT,
              "no out");
    CHECK_INT(dims_sign_dims5_url("/dims5/a/?url=" TEST_IMAGE, TEST_KEY, NULL,
                                  NULL),
              DIMS_SIGN_BAD_ARGUMENT, "no out");
}

/* Every status has a description, so an error message names the failure. */
static void
test_strerror(void)
{
    const dims_sign_status all[] = {
        DIMS_SIGN_OK, DIMS_SIGN_MEMORY, DIMS_SIGN_BAD_ARGUMENT,
        DIMS_SIGN_BAD_URL, DIMS_SIGN_BAD_FIELD, DIMS_SIGN_CRYPTO
    };
    size_t i;

    for (i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        const char *text = dims_sign_strerror(all[i]);

        CHECK(text != NULL && *text != '\0' && strcmp(text, "unknown") != 0,
              "status %d has a description", (int) all[i]);
    }
}

/* -- eurl ---------------------------------------------------------------- */

/*
 * The two derivations. The HKDF vector is checked against the value in
 * test/compose.yaml, which an independent implementation produced, in
 * test_fixtures.c. This checks the shape and the prefixes.
 */
static void
test_derive_key(void)
{
    unsigned char hkdf[DIMS_SIGN_KEY_BYTES];
    unsigned char prefixed[DIMS_SIGN_KEY_BYTES];
    unsigned char sha1[DIMS_SIGN_KEY_BYTES];

    CHECK_INT(dims_sign_derive_key(TEST_KEY, hkdf), DIMS_SIGN_OK, "hkdf");
    CHECK_INT(dims_sign_derive_key("hkdf:" TEST_KEY, prefixed), DIMS_SIGN_OK,
              "an hkdf prefix");
    CHECK(memcmp(hkdf, prefixed, sizeof(hkdf)) == 0,
          "the hkdf prefix names the default");

    /* SHA-1 of t3stk3y is f4fd45f7f87ca8d7..., and the key is the first
     * sixteen characters of that, uppercased. */
    CHECK_INT(dims_sign_derive_key("sha1:" TEST_SECRET, sha1), DIMS_SIGN_OK,
              "sha1");
    CHECK(memcmp(sha1, "F4FD45F7F87CA8D7", DIMS_SIGN_KEY_BYTES) == 0,
          "the sha1 key");

    CHECK(memcmp(hkdf, sha1, sizeof(hkdf)) != 0,
          "the two derivations differ");

    CHECK_INT(dims_sign_derive_key(NULL, hkdf), DIMS_SIGN_BAD_ARGUMENT, "no secret");
    CHECK_INT(dims_sign_derive_key("", hkdf), DIMS_SIGN_BAD_ARGUMENT, "an empty secret");
}

/* A fresh IV every call, and the tag rejects an edited value. */
static void
test_eurl_gcm(void)
{
    unsigned char key[DIMS_SIGN_KEY_BYTES];
    char *first = NULL;
    char *second = NULL;
    char *plain = NULL;

    CHECK_INT(dims_sign_derive_key(TEST_KEY, key), DIMS_SIGN_OK, "derive");

    CHECK_INT(dims_sign_eurl_encrypt("http://origin:8080/grid.png", key,
                                     DIMS_SIGN_EURL_GCM, &first),
              DIMS_SIGN_OK, "encrypt");
    CHECK_INT(dims_sign_eurl_encrypt("http://origin:8080/grid.png", key,
                                     DIMS_SIGN_EURL_GCM, &second),
              DIMS_SIGN_OK, "encrypt again");

    CHECK(strcmp(first, second) != 0, "two calls produce two values");

    CHECK_INT(dims_sign_eurl_decrypt(first, key, DIMS_SIGN_EURL_GCM, &plain),
              DIMS_SIGN_OK, "decrypt");
    CHECK_STR(plain, "http://origin:8080/grid.png", "the round trip");

    dims_sign_free(plain);
    plain = NULL;

    /* A byte of the ciphertext, past the IV. */
    first[20] = (first[20] == 'A') ? 'B' : 'A';
    CHECK_INT(dims_sign_eurl_decrypt(first, key, DIMS_SIGN_EURL_GCM, &plain),
              DIMS_SIGN_BAD_EURL, "an edited value");

    dims_sign_free(first);
    dims_sign_free(second);
}

/* ECB has no IV, so one URL under one key produces one value. */
static void
test_eurl_ecb(void)
{
    unsigned char key[DIMS_SIGN_KEY_BYTES];
    char *first = NULL;
    char *second = NULL;
    char *plain = NULL;

    CHECK_INT(dims_sign_derive_key("sha1:" TEST_SECRET, key), DIMS_SIGN_OK,
              "derive");

    CHECK_INT(dims_sign_eurl_encrypt("http://origin:8080/grid.png", key,
                                     DIMS_SIGN_EURL_ECB, &first),
              DIMS_SIGN_OK, "encrypt");
    CHECK_INT(dims_sign_eurl_encrypt("http://origin:8080/grid.png", key,
                                     DIMS_SIGN_EURL_ECB, &second),
              DIMS_SIGN_OK, "encrypt again");

    CHECK_STR(first, second, "two calls produce one value");

    CHECK_INT(dims_sign_eurl_decrypt(first, key, DIMS_SIGN_EURL_ECB, &plain),
              DIMS_SIGN_OK, "decrypt");
    CHECK_STR(plain, "http://origin:8080/grid.png", "the round trip");

    dims_sign_free(first);
    dims_sign_free(second);
    dims_sign_free(plain);
}

/* A value the decoder cannot read. */
static void
test_eurl_refuses_a_bad_value(void)
{
    unsigned char key[DIMS_SIGN_KEY_BYTES];
    char *out = untouched;

    CHECK_INT(dims_sign_derive_key(TEST_KEY, key), DIMS_SIGN_OK, "derive");

    CHECK_INT(dims_sign_eurl_decrypt("!!!!", key, DIMS_SIGN_EURL_GCM, &out),
              DIMS_SIGN_BAD_EURL, "not base64");
    CHECK_INT(dims_sign_eurl_decrypt("AAAA", key, DIMS_SIGN_EURL_GCM, &out),
              DIMS_SIGN_BAD_EURL, "shorter than an IV and a tag");
    CHECK_INT(dims_sign_eurl_decrypt("AAAA", key, DIMS_SIGN_EURL_ECB, &out),
              DIMS_SIGN_BAD_EURL, "shorter than one AES block");
    CHECK_INT(dims_sign_eurl_decrypt("", key, DIMS_SIGN_EURL_GCM, &out),
              DIMS_SIGN_BAD_EURL, "an empty value");
    CHECK_INT(dims_sign_eurl_encrypt(NULL, key, DIMS_SIGN_EURL_GCM, &out),
              DIMS_SIGN_BAD_ARGUMENT, "no URL");

    CHECK(out == untouched, "a failure leaves the out parameter untouched");
}

/* The signed URL holds eurl in place of url, and the signature is the one the
 * plain URL produces. */
static void
test_eurl_url(void)
{
    char *plain_signed = NULL;
    char *encrypted = NULL;
    const char *input = "/dims5/resize/100x100/?url=" TEST_IMAGE;
    const char *digest;

    CHECK_INT(dims_sign_dims5_url(input, TEST_KEY, NULL, &plain_signed),
              DIMS_SIGN_OK, "sign");
    CHECK_INT(dims_sign_dims5_eurl_url(input, TEST_KEY, NULL, &encrypted),
              DIMS_SIGN_OK, "sign and encrypt");

    digest = strstr(plain_signed, "&sig=");
    CHECK(digest != NULL, "the plain URL holds a signature");
    CHECK(digest != NULL && strstr(encrypted, digest) != NULL,
          "the signature covers the plain image URL");

    CHECK(strstr(encrypted, "eurl=") != NULL, "the output holds eurl");
    CHECK(strstr(encrypted, "&url=") == NULL && strncmp(encrypted, "/dims5/resize/100x100/?url=", 27) != 0,
          "the output holds no url");

    dims_sign_free(plain_signed);
    dims_sign_free(encrypted);
}

const dims_test dims_tests_unit_sign[] = {
    { "TestSignEscape", test_escape, NULL },
    { "TestSignCanonicalQueryOrdersByName",
      test_canonical_query_orders_by_name, NULL },
    { "TestSignCanonicalQueryDropsTheUnsigned",
      test_canonical_query_drops_the_unsigned, NULL },
    { "TestSignCanonicalQueryCoversTheNames",
      test_canonical_query_covers_the_names, NULL },
    { "TestSignCanonicalQueryEncodesASeparator",
      test_canonical_query_encodes_a_separator, NULL },
    { "TestSignCanonicalQueryKeepsRepeatedValues",
      test_canonical_query_keeps_repeated_values, NULL },
    { "TestSignCanonicalQueryHandlesAValuelessParameter",
      test_canonical_query_handles_a_valueless_parameter, NULL },
    { "TestSignDims5Digest", test_dims5_digest, NULL },
    { "TestSignDims5Message", test_dims5_message, NULL },
    { "TestSignDims5Equal", test_dims5_equal, NULL },
    { "TestSignDims4Digest", test_dims4_digest, NULL },
    { "TestSignDims4Equal", test_dims4_equal, NULL },
    { "TestSignFieldOk", test_field_ok, NULL },
    { "TestSignDims5Url", test_dims5_url, NULL },
    { "TestSignDims4Url", test_dims4_url, NULL },
    { "TestSignRefusesABadUrl", test_refuses_a_bad_url, NULL },
    { "TestSignAllocationContract", test_allocation_contract, NULL },
    { "TestSignStrerror", test_strerror, NULL },
    { "TestSignDeriveKey", test_derive_key, NULL },
    { "TestSignEurlGcm", test_eurl_gcm, NULL },
    { "TestSignEurlEcb", test_eurl_ecb, NULL },
    { "TestSignEurlRefusesABadValue", test_eurl_refuses_a_bad_value, NULL },
    { "TestSignEurlUrl", test_eurl_url, NULL },
    DIMS_TEST_END
};
