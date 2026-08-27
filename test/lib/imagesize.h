/*
 * Reads the pixel dimensions from an encoded image.
 *
 * The HTTP layer does not link ImageMagick, and it does not need to. Reading
 * the header is enough to report "want width 100, got 50" instead of "bytes
 * differ", which is the design rule this file exists for.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_IMAGESIZE_H
#define DIMS_TEST_IMAGESIZE_H

#include <stddef.h>

typedef struct dims_image_size {
    long width;
    long height;
    /* The number of frames. GIF only; 1 for every other format. */
    long frames;
    const char *format;
} dims_image_size;

/* Returns 0 when the header parsed. */
int dims_image_size_of(const unsigned char *body, size_t body_len, dims_image_size *size);

/* Reads the size and fails the test when the header does not parse. */
dims_image_size dims_must_size(const unsigned char *body, size_t body_len);

#endif
