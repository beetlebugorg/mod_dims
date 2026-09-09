/*
 * Reading test/fixtures/signing.tsv.
 *
 * The file is the contract the C library, the Go client, and the Java client
 * share. Both suites read it through here, so one reader states the format.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_FIXTURES_H
#define DIMS_TEST_FIXTURES_H

#define DIMS_FIXTURE_FIELD_MAX 2048

typedef struct {
    char name[128];
    char endpoint[16];
    char prefix[128];
    char key[128];
    char cipher[8];
    char input[DIMS_FIXTURE_FIELD_MAX];
    char expected[DIMS_FIXTURE_FIELD_MAX];
    char query[DIMS_FIXTURE_FIELD_MAX];
    char message[DIMS_FIXTURE_FIELD_MAX];
    char plain[DIMS_FIXTURE_FIELD_MAX];
    char error[32];
    int has_expected;
    int has_query;
    int has_message;
    int has_plain;
    int has_error;
} dims_fixture;

/* Where the file is. DIMS_TEST_FIXTURE_FILE names another one. */
const char *dims_fixtures_path(void);

/*
 * Hands every record to visit, in file order. Returns the number of records,
 * or -1 when the file cannot be read or a line is malformed.
 */
int dims_fixtures_read(void (*visit)(const dims_fixture *, void *), void *data);

/* Whether the record is for the /dims5/ endpoint. */
int dims_fixture_is_dims5(const dims_fixture *f);

/*
 * Whether the record decrypts an eurl value rather than signing a URL. Such a
 * record has cipher, input, and either plain or error.
 */
int dims_fixture_is_eurl(const dims_fixture *f);

/* The prefix to pass to the signer. An empty prefix means the default. */
const char *dims_fixture_prefix(const dims_fixture *f);

#endif
