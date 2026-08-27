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

#endif
