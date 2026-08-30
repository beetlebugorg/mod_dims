/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"
#include "geometry.h"

/*
 * The commands the /dims/ endpoint maps onto. They crop from the centre
 * rather than by gravity, which is what that endpoint always did.
 */

/**
 * Legacy API support.
 */
apr_status_t
dims_legacy_crop_operation (dims_request_rec *d, char *args, const char **err) {
    MagickStatusType flags;
    RectangleInfo rec;
    ExceptionInfo *ex_info = AcquireExceptionInfo();
    long width, height;
    int x, y;

    flags = ParseGravityGeometry(GetImageFromMagickWand(d->wand), args, &rec, ex_info);

    if(!(flags & AllValues)) {
        DestroyExceptionInfo(ex_info);

        *err = "Parsing crop geometry failed";
        return DIMS_FAILURE;
    }

    DestroyExceptionInfo(ex_info);

    width = MagickGetImageWidth(d->wand);
    height = MagickGetImageHeight(d->wand);
    x = (width / 2) - (rec.width / 2);
    y = (height / 2) - (rec.height / 2);

    rec.x = x;
    rec.y = y;

    if (!dims_geometry_crop_fits(GetImageFromMagickWand(d->wand), &rec)) {
        *err = "The crop region lies outside the image";
        return DIMS_BAD_ARGUMENTS;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
        "legacy_crop will crop to %ldx%ld+%d+%d", 
        rec.width, rec.height, x, y);

    MAGICK_CROP_CHECK(MagickCropImage(d->wand, rec.width, rec.height, rec.x, rec.y),
                      d, err, "The crop region lies outside the image");

    return DIMS_SUCCESS;
}

apr_status_t
dims_legacy_thumbnail_operation (dims_request_rec *d, char *args, const char **err) {
    MagickStatusType flags;
    RectangleInfo rec;
    long width, height;
    int x, y;
    char *resize_args = apr_psprintf(d->pool, "%s^", args);

    flags = dims_parse_size_geometry(GetImageFromMagickWand(d->wand), resize_args, &rec);
    if(!(flags & AllValues)) {
        *err = "Parsing thumbnail (resize) geometry failed";
        return DIMS_FAILURE;
    }

    dims_geometry_least_one_pixel(&rec);

    char *format = MagickGetImageFormat(d->wand);
    if (strcmp(format, "JPEG") == 0) {
        const double factors[3] = { 2.0, 1.0, 1.0 };
        MAGICK_CHECK(MagickSetSamplingFactors(d->wand, 3, factors), d);
    }
    MagickRelinquishMemory(format);

    if(rec.width < 200 && rec.height < 200) {
        MAGICK_CHECK(MagickThumbnailImage(d->wand, rec.width, rec.height), d);
    } else {
        MAGICK_CHECK(MagickScaleImage(d->wand, rec.width, rec.height), d);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
        "legacy_thumbnail will resize to %ldx%ld", rec.width, rec.height);

    flags = ParseAbsoluteGeometry(args, &rec);
    if(!(flags & AllValues)) {
        *err = "Parsing thumbnail (crop) geometry failed";
        return DIMS_FAILURE;
    }

    width = MagickGetImageWidth(d->wand);
    height = MagickGetImageHeight(d->wand);
    x = (width / 2) - (rec.width / 2);
    y = (height / 2) - (rec.height / 2);

    rec.x = x;
    rec.y = y;

    if (!dims_geometry_crop_fits(GetImageFromMagickWand(d->wand), &rec)) {
        *err = "The crop region lies outside the image";
        return DIMS_BAD_ARGUMENTS;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
        "legacy_thumbnail will crop to %ldx%ld+%d+%d", rec.width, rec.height, x, y);

    MAGICK_CROP_CHECK(MagickCropImage(d->wand, rec.width, rec.height, rec.x, rec.y),
                      d, err, "The crop region lies outside the image");

    return DIMS_SUCCESS;
}
