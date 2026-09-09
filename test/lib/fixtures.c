/*
 * Reading test/fixtures/signing.tsv.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fixtures.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DIMS_FIXTURE_FILE
#define DIMS_FIXTURE_FILE "/build/mod_dims/test/fixtures/signing.tsv"
#endif

const char *
dims_fixtures_path(void)
{
    const char *from_env = getenv("DIMS_TEST_FIXTURE_FILE");

    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : DIMS_FIXTURE_FILE;
}

/* \n, \t, and \\ are the only escapes. */
static void
unescape(const char *value, char *out, size_t size)
{
    size_t at = 0;
    size_t i;

    for (i = 0; value[i] != '\0' && at + 1 < size; i++) {
        if (value[i] == '\\' && value[i + 1] != '\0') {
            i++;
            switch (value[i]) {
                case 'n': out[at++] = '\n'; break;
                case 't': out[at++] = '\t'; break;
                default:  out[at++] = value[i]; break;
            }
        } else {
            out[at++] = value[i];
        }
    }

    out[at] = '\0';
}

static int
set_field(dims_fixture *f, const char *name, const char *value)
{
    if (strcmp(name, "case") == 0) {
        unescape(value, f->name, sizeof(f->name));
    } else if (strcmp(name, "endpoint") == 0) {
        unescape(value, f->endpoint, sizeof(f->endpoint));
    } else if (strcmp(name, "prefix") == 0) {
        unescape(value, f->prefix, sizeof(f->prefix));
    } else if (strcmp(name, "key") == 0) {
        unescape(value, f->key, sizeof(f->key));
    } else if (strcmp(name, "input") == 0) {
        unescape(value, f->input, sizeof(f->input));
    } else if (strcmp(name, "signed") == 0) {
        unescape(value, f->expected, sizeof(f->expected));
        f->has_expected = 1;
    } else if (strcmp(name, "query") == 0) {
        unescape(value, f->query, sizeof(f->query));
        f->has_query = 1;
    } else if (strcmp(name, "message") == 0) {
        unescape(value, f->message, sizeof(f->message));
        f->has_message = 1;
    } else if (strcmp(name, "error") == 0) {
        unescape(value, f->error, sizeof(f->error));
        f->has_error = 1;
    } else {
        return 0;
    }

    return 1;
}

int
dims_fixtures_read(void (*visit)(const dims_fixture *, void *), void *data)
{
    FILE *file = fopen(dims_fixtures_path(), "r");
    char line[DIMS_FIXTURE_FIELD_MAX + 128];
    dims_fixture current;
    int open = 0;
    int count = 0;

    if (file == NULL) {
        return -1;
    }

    memset(&current, 0, sizeof(current));

    while (fgets(line, (int) sizeof(line), file) != NULL) {
        char *tab;
        size_t length = strlen(line);

        while (length > 0 && (line[length - 1] == '\n' ||
                              line[length - 1] == '\r')) {
            line[--length] = '\0';
        }

        /* A blank line ends a record. */
        if (length == 0) {
            if (open) {
                visit(&current, data);
                count++;
                memset(&current, 0, sizeof(current));
                open = 0;
            }
            continue;
        }

        if (line[0] == '#') {
            continue;
        }

        tab = strchr(line, '\t');
        if (tab == NULL) {
            fclose(file);
            return -1;
        }

        *tab = '\0';
        if (!set_field(&current, line, tab + 1)) {
            fclose(file);
            return -1;
        }

        open = 1;
    }

    if (open) {
        visit(&current, data);
        count++;
    }

    fclose(file);

    return count;
}

int
dims_fixture_is_dims5(const dims_fixture *f)
{
    return strcmp(f->endpoint, "dims5") == 0;
}

const char *
dims_fixture_prefix(const dims_fixture *f)
{
    return (f->prefix[0] != '\0') ? f->prefix : NULL;
}
