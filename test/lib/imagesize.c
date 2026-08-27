/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "imagesize.h"
#include "test.h"

#include <string.h>

static long
be32(const unsigned char *p)
{
    return ((long) p[0] << 24) | ((long) p[1] << 16) | ((long) p[2] << 8) | (long) p[3];
}

static long
be16(const unsigned char *p)
{
    return ((long) p[0] << 8) | (long) p[1];
}

static long
le16(const unsigned char *p)
{
    return ((long) p[1] << 8) | (long) p[0];
}

static int
png_size(const unsigned char *body, size_t len, dims_image_size *size)
{
    static const unsigned char magic[8] = { 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a };

    if (len < 24 || memcmp(body, magic, sizeof(magic)) != 0) {
        return 1;
    }
    if (memcmp(body + 12, "IHDR", 4) != 0) {
        return 1;
    }

    size->width = be32(body + 16);
    size->height = be32(body + 20);
    size->frames = 1;
    size->format = "png";

    return 0;
}

static int
gif_size(const unsigned char *body, size_t len, dims_image_size *size)
{
    size_t offset;

    if (len < 10 || memcmp(body, "GIF8", 4) != 0) {
        return 1;
    }

    size->width = le16(body + 6);
    size->height = le16(body + 8);
    size->format = "gif";
    size->frames = 0;

    /* Count the image descriptors, which is the frame count. */
    for (offset = 0; offset + 1 < len; offset++) {
        if (body[offset] == 0x2c) {
            size->frames++;
        }
    }
    if (size->frames == 0) {
        size->frames = 1;
    }

    return 0;
}

static int
jpeg_size(const unsigned char *body, size_t len, dims_image_size *size)
{
    size_t offset = 2;

    if (len < 4 || body[0] != 0xff || body[1] != 0xd8) {
        return 1;
    }

    while (offset + 9 < len) {
        unsigned char marker;
        long segment;

        if (body[offset] != 0xff) {
            offset++;
            continue;
        }

        marker = body[offset + 1];
        /* Padding and the standalone markers carry no length. */
        if (marker == 0xff || marker == 0x01 || (marker >= 0xd0 && marker <= 0xd9)) {
            offset += 2;
            continue;
        }

        segment = be16(body + offset + 2);
        if (segment < 2) {
            return 1;
        }

        /* SOF0 through SOF15, less the four that are not frame headers. */
        if (marker >= 0xc0 && marker <= 0xcf && marker != 0xc4 && marker != 0xc8 &&
            marker != 0xcc) {
            size->height = be16(body + offset + 5);
            size->width = be16(body + offset + 7);
            size->frames = 1;
            size->format = "jpeg";
            return 0;
        }

        offset += 2 + (size_t) segment;
    }

    return 1;
}

static int
webp_size(const unsigned char *body, size_t len, dims_image_size *size)
{
    if (len < 30 || memcmp(body, "RIFF", 4) != 0 || memcmp(body + 8, "WEBP", 4) != 0) {
        return 1;
    }

    size->frames = 1;
    size->format = "webp";

    if (memcmp(body + 12, "VP8X", 4) == 0) {
        size->width = 1 + (body[24] | (body[25] << 8) | (body[26] << 16));
        size->height = 1 + (body[27] | (body[28] << 8) | (body[29] << 16));
        return 0;
    }
    if (memcmp(body + 12, "VP8L", 4) == 0) {
        unsigned int bits = (unsigned int) body[21] | ((unsigned int) body[22] << 8) |
                            ((unsigned int) body[23] << 16) | ((unsigned int) body[24] << 24);
        size->width = (long) (bits & 0x3fff) + 1;
        size->height = (long) ((bits >> 14) & 0x3fff) + 1;
        return 0;
    }
    if (memcmp(body + 12, "VP8 ", 4) == 0) {
        size->width = le16(body + 26) & 0x3fff;
        size->height = le16(body + 28) & 0x3fff;
        return 0;
    }

    return 1;
}

int
dims_image_size_of(const unsigned char *body, size_t body_len, dims_image_size *size)
{
    memset(size, 0, sizeof(*size));

    if (body == NULL || body_len == 0) {
        return 1;
    }

    if (png_size(body, body_len, size) == 0) {
        return 0;
    }
    if (gif_size(body, body_len, size) == 0) {
        return 0;
    }
    if (jpeg_size(body, body_len, size) == 0) {
        return 0;
    }
    if (webp_size(body, body_len, size) == 0) {
        return 0;
    }

    return 1;
}

dims_image_size
dims_must_size(const unsigned char *body, size_t body_len)
{
    dims_image_size size;

    if (dims_image_size_of(body, body_len, &size) != 0) {
        FAIL("the response is not an image this suite can read (%zu bytes)", body_len);
    }

    return size;
}
