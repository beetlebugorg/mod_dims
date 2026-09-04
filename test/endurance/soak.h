/*
 * The soak client.
 *
 * It builds a signed request, sends it, and compares the response against the
 * expected result. Every choice comes from one seeded generator, so a run with
 * the same seed sends the same requests.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_SOAK_H
#define DIMS_SOAK_H

#include <stddef.h>
#include <stdint.h>

/* -- The corpus ------------------------------------------------------- */

/*
 * What each source must do. The corpus builder decides this by reading the
 * file through the same ImageMagick the module runs, under the same policy.
 */
typedef enum {
    DIMS_CLASS_IMAGE,   /* decodes, so a valid request must return an image */
    DIMS_CLASS_REJECT,  /* does not decode, so every request for it must fail */
    DIMS_CLASS_EITHER   /* large, multi-frame, or guarded: both results are allowed */
} dims_source_class;

typedef struct {
    char *name;
    char *format;
    long bytes;
    dims_source_class klass;
} dims_source;

typedef struct {
    dims_source *items;
    size_t count;
    /* Indexes into items, split by class, so a draw can weight them. */
    size_t *image;
    size_t image_count;
    size_t *reject;
    size_t reject_count;
    size_t *either;
    size_t either_count;
} dims_corpus;

int dims_corpus_load(dims_corpus *corpus, const char *path);
void dims_corpus_free(dims_corpus *corpus);
const char *dims_class_name(dims_source_class klass);

/* -- The generator ----------------------------------------------------- */

/* splitmix64. It produces the same sequence on every platform. */
typedef struct {
    uint64_t state;
} dims_rng;

void dims_rng_seed(dims_rng *rng, uint64_t seed);
uint64_t dims_rng_next(dims_rng *rng);
uint32_t dims_rng_below(dims_rng *rng, uint32_t bound);
int dims_rng_chance(dims_rng *rng, int percent);

/* -- Signing ----------------------------------------------------------- */

/*
 * Percent-encodes a value the way the module does when it rebuilds the query
 * it signed: unreserved characters pass, a space becomes a plus, everything
 * else becomes an uppercase hexadecimal pair. The caller frees.
 */
char *dims_escape(const char *value);

/*
 * The same, for a path segment. A slash separates the commands, so it passes
 * through. The caller frees.
 */
char *dims_escape_path(const char *value);

/* Hexadecimal MD5 of message. The caller frees. */
char *dims_md5_hex(const char *message);

/* Hexadecimal HMAC-SHA256 of message under key. The caller frees. */
char *dims_hmac_sha256_hex(const char *key, const char *message);

/* HKDF-SHA256 with the salt the module uses. Returns 0 on failure. */
int dims_key_hkdf(const char *secret, unsigned char key[16]);

/* SHA-1 of the secret, hexadecimal, the first sixteen characters uppercased. */
int dims_key_sha1(const char *secret, unsigned char key[16]);

/*
 * Encrypts url with AES-128-GCM and returns base64 of the IV, the ciphertext,
 * and the tag, in that order. The IV comes from the generator, so the same
 * seed produces the same eurl. The caller frees.
 */
char *dims_eurl_gcm(const unsigned char key[16], const char *url, dims_rng *rng);

/* AES-128-ECB with PKCS5 padding, base64 encoded. The caller frees. */
char *dims_eurl_ecb(const unsigned char key[16], const char *url);

/* -- The response body -------------------------------------------------- */

/*
 * Returns the name of the image format the first bytes hold. Returns NULL for
 * a format this file does not know. The returned name is static.
 */
const char *dims_body_format(const unsigned char *body, size_t length);

/* -- A planned request --------------------------------------------------- */

typedef enum {
    DIMS_EXPECT_IMAGE,   /* a 2xx status and an image body */
    DIMS_EXPECT_REFUSE,  /* anything but a 2xx */
    DIMS_EXPECT_ANY      /* only a transport failure is a failure */
} dims_expect;

/* The mutations applied after signing. The report names each one. */
typedef enum {
    DIMS_TAMPER_NONE = 0,
    DIMS_TAMPER_FLIP_SIGNATURE,
    DIMS_TAMPER_SHORT_SIGNATURE,
    DIMS_TAMPER_SIX_SIGNATURE,
    DIMS_TAMPER_UPPER_SIGNATURE,
    DIMS_TAMPER_NO_SIGNATURE,
    DIMS_TAMPER_EXPIRED,
    DIMS_TAMPER_FAR_FUTURE,
    DIMS_TAMPER_WRONG_CLIENT,
    DIMS_TAMPER_REWRITE_COMMANDS,
    DIMS_TAMPER_SWAP_URL,
    DIMS_TAMPER_EXTRA_PARAM,
    DIMS_TAMPER_REORDER_QUERY,
    DIMS_TAMPER_DUPLICATE_URL,
    DIMS_TAMPER_CONTROL_CHARACTER,
    DIMS_TAMPER_COUNT
} dims_tamper;

typedef enum {
    DIMS_ENDPOINT_DIMS3 = 0,
    DIMS_ENDPOINT_DIMS4,
    DIMS_ENDPOINT_DIMS5,
    DIMS_ENDPOINT_COUNT
} dims_endpoint;

typedef struct {
    char *path;                 /* the request path, query included */
    char *commands;             /* the command chain, for the failure log */
    const char *source;         /* the corpus entry, or NULL */
    dims_endpoint endpoint;
    dims_tamper tamper;
    dims_expect expect;
    int conditional;            /* sends If-None-Match, so a 304 is allowed */
    int hostile_argument;       /* an argument outside what an operation reads */
    uint64_t seq;               /* the request number, for the failure log */
} dims_plan;

/*
 * Which requests a run builds.
 *
 * mixed drives every source and every mutation, so it reports what the module
 * does with a hostile caller. safe drives only requests a decodable source
 * must answer with an image, so a refusal is a failure and the run measures
 * throughput.
 */
typedef enum {
    DIMS_PROFILE_MIXED = 0,
    DIMS_PROFILE_SAFE
} dims_profile;

typedef struct {
    const char *origin;         /* where a source lives, http://origin:8080 */
    const char *client;
    const char *secret;
    const char *signing_key;
    const char *overlay;        /* the overlay URL the watermark uses */
    const dims_corpus *corpus;
    int use_eurl;               /* encrypt the source URL some of the time */
    /* /dims4/ decrypts with the algorithm DimsEncryptionAlgorithm names.
     * /dims5/ has only the one, so this does not reach it. */
    int eurl_ecb;
    dims_profile profile;
} dims_world;

void dims_plan_make(dims_plan *plan, const dims_world *world, dims_rng *rng,
                    uint64_t sequence);
void dims_plan_free(dims_plan *plan);

const char *dims_endpoint_name(dims_endpoint endpoint);
const char *dims_tamper_name(dims_tamper tamper);
const char *dims_expect_name(dims_expect expect);

#endif
