/*
 * Reading a Prometheus exposition body in a case.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "prometheus.h"

#include <stdlib.h>
#include <string.h>

/* The body with a terminator on the end. The caller frees it. */
static char *
body_string(const dims_response *response)
{
    char *copy;

    if (response == NULL || response->body == NULL) {
        return NULL;
    }

    copy = malloc(response->body_len + 1);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, response->body, response->body_len);
    copy[response->body_len] = '\0';

    return copy;
}

int
dims_prom_contains(const dims_response *response, const char *text)
{
    char *body = body_string(response);
    int found;

    if (body == NULL) {
        return 0;
    }

    found = strstr(body, text) != NULL;
    free(body);

    return found;
}

double
dims_prom_value(const dims_response *response, const char *prefix)
{
    char *body = body_string(response);
    size_t len = strlen(prefix);
    char *line;
    char *state = NULL;
    double value = -1;

    if (body == NULL) {
        return -1;
    }

    for (line = strtok_r(body, "\n", &state); line != NULL;
            line = strtok_r(NULL, "\n", &state)) {
        /* A sample is the name, its labels, a space, and the value. Comparing
         * the space as well keeps dims_requests_total apart from
         * dims_requests_total_something. */
        if (strncmp(line, prefix, len) == 0 && line[len] == ' ') {
            value = strtod(line + len + 1, NULL);
            break;
        }
    }

    free(body);

    return value;
}
