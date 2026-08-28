/*
 * eurl decryption.
 *
 * These call the two decryption functions directly, which is the only way to
 * reach them under the sanitizers: the HTTP path needs a server, and the
 * sanitizer job builds this binary alone.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "encryption.h"
#include "fixture.h"
#include "../lib/test.h"

#include <apr_base64.h>
#include <apr_general.h>
#include <openssl/evp.h>
#include <string.h>

/* Any key. None of these cases decrypt successfully. */
static unsigned char key[17] = "0123456789ABCDEF";

/*
 * The fixture owns a pool, so each case releases it. The wand and the image
 * are not used here; the pool and the log are.
 */
#define WITH_REQUEST(name)                              \
    dims_request_rec *fixture = dims_fixture_request("grid.png", NULL); \
    request_rec *name = (fixture != NULL) ? fixture->r : NULL;          \
    if (name == NULL) {                                 \
        return;                                         \
    }

/*
 * A value that decodes to fewer bytes than an IV and a tag made
 * ciphertext_length negative. tag then pointed before the buffer, apr_palloc
 * received the negative length as a size near its maximum, and
 * EVP_DecryptUpdate received it as a length.
 */
static void
test_gcm_rejects_a_short_value(void)
{
    static const char *const shorter_than_a_header[] = {
        "", "A", "AAAA", "AAAAAAAA", "AAAAAAAAAAAA",
        /* 28 bytes exactly: an IV and a tag with no ciphertext between. */
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        NULL
    };
    WITH_REQUEST(r);
    int i;

    for (i = 0; shorter_than_a_header[i] != NULL; i++) {
        char *result = aes_128_gcm_decrypt(r, key,
                (unsigned char *) shorter_than_a_header[i]);

        CHECK(result == NULL, "a %zu character eurl must be refused",
              strlen(shorter_than_a_header[i]));
    }

    dims_fixture_free(fixture);
}

static void
test_gcm_rejects_no_value(void)
{
    WITH_REQUEST(r);

    CHECK(aes_128_gcm_decrypt(r, key, NULL) == NULL, "no eurl at all");

    dims_fixture_free(fixture);
}

/*
 * A value long enough to survive the length check still fails the tag, which
 * is what proves the check refuses the short ones for their length and not by
 * refusing everything.
 */
static void
test_gcm_rejects_a_wrong_tag(void)
{
    /* 45 bytes of zeros, which is an IV, ciphertext, and a tag by size. */
    static const unsigned char zeros[45] = { 0 };
    WITH_REQUEST(r);
    char encoded[128];

    apr_base64_encode(encoded, (const char *) zeros, (int) sizeof(zeros));

    CHECK(aes_128_gcm_decrypt(r, key, (unsigned char *) encoded) == NULL,
          "a value whose tag does not verify");

    dims_fixture_free(fixture);
}

/*
 * The ECB path allocated exactly the ciphertext length and then wrote a
 * terminator at the end of the plaintext, which lands past the allocation when
 * decryption fills the block.
 *
 * This encrypts one block, decrypts it back, and checks the round trip. Under
 * the sanitizers the write past the end is the failure; without them the
 * content is.
 */
static void
test_ecb_round_trip_terminates_inside_the_buffer(void)
{
    const char *plain = "0123456789abcde";  /* 15 bytes, one padded block */
    unsigned char ciphertext[64];
    WITH_REQUEST(r);
    EVP_CIPHER_CTX *ctx;
    int out_length = 0, final_length = 0;
    char *decrypted;

    ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx != NULL, "a cipher context");
    if (ctx == NULL) {
        dims_fixture_free(fixture);
        return;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &out_length,
                      (const unsigned char *) plain, (int) strlen(plain));
    EVP_EncryptFinal_ex(ctx, ciphertext + out_length, &final_length);
    EVP_CIPHER_CTX_free(ctx);

    decrypted = aes_128_decrypt(r, key, ciphertext, out_length + final_length);

    CHECK(decrypted != NULL, "one block must decrypt");
    if (decrypted != NULL) {
        CHECK(strcmp(decrypted, plain) == 0, "the round trip: want %s, got %s",
              plain, decrypted);
    }

    dims_fixture_free(fixture);
}

/* Shorter than one block is not a ciphertext this can decrypt. */
static void
test_ecb_rejects_a_short_value(void)
{
    static const unsigned char shorter_than_a_block[15] = { 0 };
    WITH_REQUEST(r);

    CHECK(aes_128_decrypt(r, key, (unsigned char *) shorter_than_a_block,
                          (int) sizeof(shorter_than_a_block)) == NULL,
          "a value shorter than one block");
    CHECK(aes_128_decrypt(r, key, (unsigned char *) shorter_than_a_block, 0) == NULL,
          "a value of no length");
    CHECK(aes_128_decrypt(r, key, (unsigned char *) shorter_than_a_block, -1) == NULL,
          "a negative length");
    CHECK(aes_128_decrypt(r, key, NULL, 16) == NULL, "no value at all");

    dims_fixture_free(fixture);
}

/*
 * HKDF-SHA256 over the secret, with the fixed salt. A change to the salt, the
 * hash, or the length invalidates every eurl a caller holds.
 */
static void
test_derive_key_hkdf(void)
{
    unsigned char key[DIMS_AES_KEY_BYTES];
    unsigned char again[DIMS_AES_KEY_BYTES];
    unsigned char other[DIMS_AES_KEY_BYTES];
    unsigned char prefixed[DIMS_AES_KEY_BYTES];

    CHECK(dims_derive_key("a-secret", key), "a secret derives a key");
    CHECK(dims_derive_key("a-secret", again), "and again");
    CHECK(memcmp(key, again, sizeof(key)) == 0, "the same secret, the same key");

    CHECK(dims_derive_key("another", other), "another secret");
    CHECK(memcmp(key, other, sizeof(key)) != 0, "a different secret, a different key");

    /* The hkdf: prefix selects this path and is not part of the secret. */
    CHECK(dims_derive_key("hkdf:a-secret", prefixed), "a prefixed secret");
    CHECK(memcmp(key, prefixed, sizeof(key)) == 0,
          "hkdf:a-secret and a-secret derive the same key");

    CHECK(!dims_derive_key(NULL, key), "no secret");
}

/*
 * A sha1: prefix takes the older path: SHA-1 of the rest, hex encoded, the
 * first 16 characters uppercased.
 */
static void
test_derive_key_sha1(void)
{
    unsigned char key[DIMS_AES_KEY_BYTES];
    unsigned char hkdf[DIMS_AES_KEY_BYTES];
    int i;

    CHECK(dims_derive_key("sha1:a-secret", key), "a sha1 secret");

    for (i = 0; i < DIMS_AES_KEY_BYTES; i++) {
        CHECK((key[i] >= '0' && key[i] <= '9') || (key[i] >= 'A' && key[i] <= 'F'),
              "byte %d is an uppercase hex character, got %c", i, key[i]);
    }

    CHECK(dims_derive_key("a-secret", hkdf), "the same secret without the prefix");
    CHECK(memcmp(key, hkdf, sizeof(key)) != 0,
          "the two paths must not agree");
}

const dims_test dims_tests_unit_encryption[] = {
    { "TestGcmRejectsAShortValue", test_gcm_rejects_a_short_value, NULL },
    { "TestGcmRejectsNoValue", test_gcm_rejects_no_value, NULL },
    { "TestGcmRejectsAWrongTag", test_gcm_rejects_a_wrong_tag, NULL },
    { "TestEcbRoundTripTerminatesInsideTheBuffer",
      test_ecb_round_trip_terminates_inside_the_buffer, NULL },
    { "TestEcbRejectsAShortValue", test_ecb_rejects_a_short_value, NULL },
    { "TestDeriveKeyHkdf", test_derive_key_hkdf, NULL },
    { "TestDeriveKeySha1", test_derive_key_sha1, NULL },
    DIMS_TEST_END
};
