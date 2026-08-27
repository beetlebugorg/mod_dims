/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "geometry.h"

/*
 * ParseSizeGeometry, written out.
 *
 * ImageMagick 6 deprecated it and ImageMagick 7 removed it. Its whole body was
 * these two calls: seed the rectangle from the image, then let the geometry
 * string modify it. Both survive into version 7, so writing it out here is
 * what makes the module portable.
 *
 * This is deliberately landed while still building against version 6, so the
 * golden files prove the two are the same. They do: no baseline moves.
 */
MagickStatusType
dims_parse_size_geometry(const Image *image, const char *geometry,
                         RectangleInfo *region)
{
    SetGeometry(image, region);

    return ParseMetaGeometry(geometry, &region->x, &region->y, &region->width,
                             &region->height);
}
