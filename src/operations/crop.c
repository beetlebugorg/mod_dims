/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"
#include "geometry.h"

apr_status_t
dims_crop_operation (dims_request_rec *d, char *args, const char **err) {
    MagickStatusType flags;
    RectangleInfo rec;
    ExceptionInfo *ex_info = AcquireExceptionInfo();

    /* Replace spaces with '+'. This happens when some user agents inadvertantly 
     * escape the '+' as %20 which gets converted to a space.
     * 
     * Example: 
     * 
     * 900x900%20350%200 is '900x900 350 0' which is an invalid, the following code
     * coverts this to '900x900+350+0'.
     *
     */
    char *s = args;
    while (*s) {
        if (*s == ' ') {
            *s = '+';
        }

        s++;
    }


    flags = ParseGravityGeometry(GetImageFromMagickWand(d->wand), args, &rec, ex_info);
    if(!(flags & AllValues)) {
        DestroyExceptionInfo(ex_info);

        *err = "Parsing crop geometry failed";
        return DIMS_FAILURE;
    }

    DestroyExceptionInfo(ex_info);

    /* A region that lies off the image has nothing to cut out. go-dims answers
     * 400 for it, and a signature is portable between the two. */
    if (!dims_geometry_crop_fits(GetImageFromMagickWand(d->wand), &rec)) {
        *err = "The crop region lies outside the image";
        return DIMS_BAD_ARGUMENTS;
    }

    MAGICK_CROP_CHECK(MagickCropImage(d->wand, rec.width, rec.height, rec.x, rec.y),
                      d, err, "The crop region lies outside the image");
    MAGICK_CHECK(MagickSetImagePage(d->wand, rec.width, rec.height, rec.x, rec.y), d);

    return DIMS_SUCCESS;
}
