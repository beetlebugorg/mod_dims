/*
 * The shared signing fixtures, against the C library.
 *
 * test/fixtures/signing.tsv is the contract the three clients share. This
 * signs each input and compares every field.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dims_sign.h>
#include <dims_sign_internal.h>

#include "../lib/fixtures.h"
#include "../lib/test.h"

#include <stdio.h>
#include <string.h>

#ifndef DIMS_SIGN_COMMAND
#define DIMS_SIGN_COMMAND "/build/mod_dims/build/sign/dims-sign"
#endif

static const char *
error_name(dims_sign_status status)
{
    switch (status) {
        case DIMS_SIGN_BAD_FIELD:
            return "bad-field";
        case DIMS_SIGN_BAD_ARGUMENT:
            return "bad-argument";
        default:
            return "bad-url";
    }
}

static void
check_signed(const dims_fixture *f)
{
    char *got = NULL;
    dims_sign_status status;

    status = dims_fixture_is_dims5(f)
            ? dims_sign_dims5_url(f->input, f->key, dims_fixture_prefix(f), &got)
            : dims_sign_dims4_url(f->input, f->key, dims_fixture_prefix(f), &got);

    if (f->has_error) {
        CHECK(status != DIMS_SIGN_OK, "%s: the signer must refuse the input",
              f->name);
        CHECK_STR(error_name(status), f->error, f->name);
        dims_sign_free(got);
        return;
    }

    CHECK(f->has_expected, "%s: a record needs signed or error", f->name);

    if (status != DIMS_SIGN_OK) {
        FAIL("%s: %s", f->name, dims_sign_strerror(status));
        return;
    }

    CHECK_STR(got, f->expected, f->name);
    dims_sign_free(got);
}

static void
check_query(const dims_fixture *f)
{
    const char *args;
    char *got = NULL;

    if (!f->has_query) {
        return;
    }

    CHECK(dims_fixture_is_dims5(f),
          "%s: only a /dims5/ record has a canonical query", f->name);

    args = strchr(f->input, '?');
    CHECK_INT(dims_sign_canonical_query((args != NULL) ? args + 1 : NULL, &got),
              DIMS_SIGN_OK, f->name);
    CHECK_STR(got, f->query, f->name);
    dims_sign_free(got);
}

static void
check_message(const dims_fixture *f)
{
    char *got = NULL;
    dims_sign_status status;

    if (!f->has_message) {
        return;
    }

    status = dims_fixture_is_dims5(f)
            ? dims_sign_dims5_message(f->input, dims_fixture_prefix(f), &got)
            : dims_sign_dims4_message(f->input, f->key, dims_fixture_prefix(f),
                                      &got);

    if (status != DIMS_SIGN_OK) {
        FAIL("%s: %s", f->name, dims_sign_strerror(status));
        return;
    }

    CHECK_STR(got, f->message, f->name);
    dims_sign_free(got);
}

static void
check_record(const dims_fixture *f, void *data)
{
    (void) data;

    CHECK(f->name[0] != '\0', "a record needs a case name");
    CHECK(f->input[0] != '\0', "%s: a record needs an input", f->name);

    check_signed(f);
    check_query(f);
    check_message(f);
}

/* Every field of every record, against the library. */
static void
test_fixtures(void)
{
    int count = dims_fixtures_read(check_record, NULL);

    CHECK(count >= 30, "the fixture file holds the cases, got %d", count);
}

/*
 * The file is what dims-sign writes. A change to the library that moves a
 * value fails here, and the difference names the line.
 */
static void
test_fixture_round_trip(void)
{
    char command[1024];
    FILE *wrote;
    FILE *have;
    int line = 1;

    snprintf(command, sizeof(command), "%s --fixture < %s", DIMS_SIGN_COMMAND,
             dims_fixtures_path());

    wrote = popen(command, "r");
    if (wrote == NULL) {
        FAIL("cannot run %s", command);
        return;
    }

    have = fopen(dims_fixtures_path(), "r");
    if (have == NULL) {
        pclose(wrote);
        FAIL("cannot open %s", dims_fixtures_path());
        return;
    }

    for (;;) {
        char produced[DIMS_FIXTURE_FIELD_MAX + 128];
        char stored[DIMS_FIXTURE_FIELD_MAX + 128];
        char *a = fgets(produced, (int) sizeof(produced), wrote);
        char *b = fgets(stored, (int) sizeof(stored), have);

        if (a == NULL && b == NULL) {
            break;
        }

        if (a == NULL || b == NULL || strcmp(produced, stored) != 0) {
            FAIL("line %d differs:\n  wrote [%s]\n  file  [%s]", line,
                 (a != NULL) ? produced : "(end)",
                 (b != NULL) ? stored : "(end)");
            break;
        }

        line++;
    }

    fclose(have);
    CHECK_INT(pclose(wrote), 0, "dims-sign --fixture");
}

const dims_test dims_tests_unit_fixtures[] = {
    { "TestSigningFixtures", test_fixtures, NULL },
    { "TestSigningFixtureRoundTrip", test_fixture_round_trip, NULL },
    DIMS_TEST_END
};
