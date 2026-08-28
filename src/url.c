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
    /*
     * Both schemes are searched, and whichever appears first in the path wins.
     *
     * The module looked for "http:/" alone. "https:/" does not contain it, so
     * a TLS source in the path was never found and the request failed as a bad
     * URL. Only the query parameter forms reached an https origin.
     */
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
     * caller escaped it and the URL is already whole.
     *
     * The repair copies, which matters: the caller truncates subject at *start
     * to keep the commands, and a URL pointing into subject would lose its
     * tail. A URL that needs no repair is already past that point.
     */
    if (at[length] == '/') {
        return apr_pstrdup(pool, at);
    }

    return apr_psprintf(pool, "%.*s//%s", (int) (length - 1), at, at + length);
}
