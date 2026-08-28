/*
 * Reading a source URL out of a request.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "url.h"

#include <string.h>

char *
dims_path_image_url(apr_pool_t *pool, char *subject, char **start)
{
    /* Both schemes are searched. Whichever appears first in the path wins. */
    static const char *const schemes[] = { "http:/", "https:/", NULL };
    const char *scheme = NULL;
    char *at = NULL;
    size_t length;
    int i;

    if (subject == NULL) {
        return NULL;
    }

    for (i = 0; schemes[i] != NULL; i++) {
        char *found = strstr(subject, schemes[i]);

        if (found != NULL && (at == NULL || found < at)) {
            at = found;
            scheme = schemes[i];
        }
    }

    if (at == NULL) {
        return NULL;
    }

    if (start != NULL) {
        *start = at;
    }

    length = strlen(scheme);

    /*
     * One slash means httpd collapsed the pair, so put it back. Two means the
     * URL is already whole.
     *
     * Both forms copy, because the caller truncates subject at *start and a
     * URL pointing into it would lose its tail.
     */
    if (at[length] == '/') {
        return apr_pstrdup(pool, at);
    }

    return apr_psprintf(pool, "%.*s//%s", (int) (length - 1), at, at + length);
}

const char *
dims_param_value(const char *token, const char *name)
{
    size_t length;

    if (token == NULL || name == NULL) {
        return NULL;
    }

    length = strlen(name);
    if (strncmp(token, name, length) != 0) {
        return NULL;
    }

    /* Past the equals sign the name carries. */
    return token + length;
}

int
dims_endpoint_prefix(const char *uri)
{
    return uri != NULL && (strncmp(uri, "/dims3/", DIMS_ENDPOINT_PREFIX_LEN) == 0 ||
                           strncmp(uri, "/dims4/", DIMS_ENDPOINT_PREFIX_LEN) == 0);
}
