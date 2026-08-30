/*
 * Naming the format a response body holds.
 *
 * The client does not link ImageMagick. A request for an image must not be
 * answered with an error page, and the first bytes of the body name the
 * format that arrived.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "soak.h"

#include <string.h>

static int
starts_with(const unsigned char *body, size_t length, const char *magic,
            size_t magic_length)
{
    return length >= magic_length && memcmp(body, magic, magic_length) == 0;
}

const char *
dims_body_format(const unsigned char *body, size_t length)
{
    if (body == NULL || length < 4) {
        return NULL;
    }

    if (starts_with(body, length, "\xFF\xD8\xFF", 3)) {
        return "jpeg";
    }
    if (starts_with(body, length, "\x89PNG\r\n\x1A\n", 8)) {
        return "png";
    }
    if (starts_with(body, length, "GIF87a", 6) ||
            starts_with(body, length, "GIF89a", 6)) {
        return "gif";
    }
    if (length >= 12 && memcmp(body, "RIFF", 4) == 0 &&
            memcmp(body + 8, "WEBP", 4) == 0) {
        return "webp";
    }
    if (starts_with(body, length, "II\x2A\x00", 4) ||
            starts_with(body, length, "MM\x00\x2A", 4)) {
        return "tiff";
    }
    if (starts_with(body, length, "BM", 2)) {
        return "bmp";
    }
    if (starts_with(body, length, "P1", 2) || starts_with(body, length, "P2", 2) ||
            starts_with(body, length, "P3", 2) || starts_with(body, length, "P4", 2) ||
            starts_with(body, length, "P5", 2) || starts_with(body, length, "P6", 2)) {
        return "pnm";
    }
    if (starts_with(body, length, "\x00\x00\x01\x00", 4)) {
        return "ico";
    }

    /*
     * SVG. The module answers with the source format when no format command
     * asked for another, so an SVG source comes back as XML text.
     */
    {
        size_t i = 0;

        if (length >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF) {
            i = 3;
        }
        while (i < length && (body[i] == ' ' || body[i] == '\t' ||
                body[i] == '\r' || body[i] == '\n')) {
            i++;
        }
        if (i < length && body[i] == '<') {
            /* An error page is HTML, and an HTML response to a request for an
             * image is a failure, so the two have to be told apart. */
            if (length - i >= 5 &&
                    (strncasecmp((const char *) body + i, "<html", 5) == 0 ||
                     strncasecmp((const char *) body + i, "<!doc", 5) == 0)) {
                return NULL;
            }
            return "svg";
        }
    }

    return NULL;
}
