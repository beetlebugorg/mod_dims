/*
 * Geometry parsing shared by the operations that resize.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_GEOMETRY_H
#define _DIMS_GEOMETRY_H

#include "operations.h"

/*
 * ParseSizeGeometry, written out.
 *
 * ImageMagick 6 deprecated it and ImageMagick 7 removed it. Its body was these
 * two calls: seed the rectangle from the image, then let the geometry string
 * modify it. Both survive into version 7.
 */
MagickStatusType dims_parse_size_geometry(const Image *image, const char *geometry,
                                          RectangleInfo *region);

/*
 * Completes a crop region and reports whether any of it lies on the image.
 *
 * A side of zero becomes the rest of the image, measured from the offset.
 * Returns 0 when nothing remains, which happens when the offset sits at or
 * past an edge. ImageMagick refuses that crop, and go-dims answers 400 for the
 * same region, so the caller returns DIMS_BAD_ARGUMENTS and the two agree.
 */
int dims_geometry_crop_fits(const Image *image, RectangleInfo *region);

/*
 * Raises a width or a height of zero to one.
 *
 * A percentage rounds down, so a small enough image scaled by a small enough
 * percentage asks for a side of no pixels. No format holds such an image, and
 * ImageMagick refuses to build one.
 */
void dims_geometry_least_one_pixel(RectangleInfo *region);

#endif
