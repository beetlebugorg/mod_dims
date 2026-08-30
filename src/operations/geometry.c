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

int
dims_geometry_crop_fits(const Image *image, RectangleInfo *region)
{
    ssize_t columns = (ssize_t) image->columns;
    ssize_t rows = (ssize_t) image->rows;
    ssize_t left = (region->x > 0) ? region->x : 0;
    ssize_t top = (region->y > 0) ? region->y : 0;

    /*
     * A side of zero means the rest of the image. ParseGravityGeometry fills
     * that in from the image, ParseAbsoluteGeometry does not, so the callers
     * that use the second one arrive here with one.
     */
    if (region->width == 0 && columns > left) {
        region->width = (size_t) (columns - left);
    }
    if (region->height == 0 && rows > top) {
        region->height = (size_t) (rows - top);
    }

    if (region->width == 0 || region->height == 0) {
        return 0;
    }

    /* Wholly right of, below, left of, or above the image. */
    if (region->x >= columns || region->y >= rows ||
            region->x + (ssize_t) region->width <= 0 ||
            region->y + (ssize_t) region->height <= 0) {
        return 0;
    }

    return 1;
}

void
dims_geometry_least_one_pixel(RectangleInfo *region)
{
    if (region->width == 0) {
        region->width = 1;
    }

    if (region->height == 0) {
        region->height = 1;
    }
}
