/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"
#include "geometry.h"

apr_status_t
dims_thumbnail_operation (dims_request_rec *d, char *args, const char **err) {
    MagickStatusType flags;
    RectangleInfo rec;
    char *resize_args = apr_psprintf(d->pool, "%s^", args);

    flags = dims_parse_size_geometry(GetImageFromMagickWand(d->wand), resize_args, &rec);
    if(!(flags & AllValues)) {
        *err = "Parsing thumbnail (resize) geometry failed";
        return DIMS_FAILURE;
    }

    char *format = MagickGetImageFormat(d->wand);
    if (strcmp(format, "JPEG") == 0) {
        const double factors[3] = { 2.0, 1.0, 1.0 };
        MAGICK_CHECK(MagickSetSamplingFactors(d->wand, 3, factors), d);
    }
    MagickRelinquishMemory(format);

    if (d->optimize_resize) {
        size_t orig_width;
        size_t orig_height;

        RectangleInfo sampleRec = rec;
        sampleRec.width *= d->optimize_resize;
        sampleRec.height *= d->optimize_resize;

        orig_width = MagickGetImageWidth(d->wand);
        orig_height = MagickGetImageHeight(d->wand);

        if(sampleRec.width < orig_width && sampleRec.height < orig_height) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Sampling image down to %zdx%zd before resizing.", sampleRec.width, sampleRec.height);
            MAGICK_CHECK(MagickSampleImage(d->wand, sampleRec.width, sampleRec.height), d);
        }
    }

    MAGICK_CHECK(MagickThumbnailImage(d->wand, rec.width, rec.height), d);

    if(!(flags & PercentValue)) {
        flags = ParseAbsoluteGeometry(args, &rec);
        if(!(flags & AllValues)) {
            *err = "Parsing thumbnail (crop) geometry failed";
            return DIMS_FAILURE;
        }

        MAGICK_CHECK(MagickCropImage(d->wand, rec.width, rec.height, rec.x, rec.y), d);
    }

    MAGICK_CHECK(MagickSetImagePage(d->wand, rec.width, rec.height, rec.x, rec.y), d);
    
    return DIMS_SUCCESS;
}
