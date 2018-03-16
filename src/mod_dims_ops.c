/*
 * Copyright 2009 AOL LLC 
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at 
 *         
 *         http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#include "mod_dims.h"

#define MAGICK_CHECK(func, rec) \
    do { \
        apr_status_t code = func; \
        if(rec->status == DIMS_IMAGEMAGICK_TIMEOUT) {\
            return DIMS_IMAGEMAGICK_TIMEOUT; \
        } else if(code == MagickFalse) {\
            return DIMS_FAILURE; \
        } \
    } while(0)

/*
apr_status_t
dims_smart_crop_operation (dims_request_rec *d, char *args, char **err) {
    MagickStatusType flags;
    RectangleInfo rec;
    ExceptionInfo ex_info;

    flags = ParseGravityGeometry(GetImageFromMagickWand(d->wand), args, &rec, &ex_info);
    if(!(flags & AllValues)) {
        *err = "Parsing crop geometry failed";
        return DIMS_FAILURE;
    }

    // MAGICK_CHECK(MagickResizeImage(d->wand, rec.width, rec.height, UndefinedFilter, 1), d);
    smartCrop(d->wand, 20, rec.width, rec.height);

    return DIMS_SUCCESS;
}
*/

apr_status_t
dims_strip_operation (dims_request_rec *d, char *args, char **err) {

    /* If args is passed from the user and 
     *   a) it equals true, strip the image.
     *   b) it equals false, don't strip the image.
     *   c) it is neither true/false, strip based on config value.
     * If args is NULL, strip based on config value.
     */
    if(args != NULL) {
        if(strcmp(args, "true") == 0 || ( strcmp(args, "false") != 0 && d->config->strip_metadata )) {
            MAGICK_CHECK(MagickStripImage(d->wand), d);
        }
    }
    else if(d->config->strip_metadata) {
        MAGICK_CHECK(MagickStripImage(d->wand), d);
    }

    return DIMS_SUCCESS;
}

apr_status_t
dims_resize_operation (dims_request_rec *d, char *args, char **err) {
    MagickStatusType flags;
    RectangleInfo rec;

    flags = ParseSizeGeometry(GetImageFromMagickWand(d->wand), args, &rec);
    if(!(flags & AllValues)) {
        *err = "Parsing thumbnail geometry failed";
        return DIMS_FAILURE;
    }

    char *format = MagickGetImageFormat(d->wand);
    if (strcmp(format, "JPEG") == 0) {
        double factors[3] = { 2.0, 1.0, 1.0 };
        MAGICK_CHECK(MagickSetSamplingFactors(d->wand, 3, &factors), d);
    }

    if (d->optimize_resize) {
        size_t orig_width;
        size_t orig_height;

        RectangleInfo sampleRec = rec;
        sampleRec.width *= d->optimize_resize;
        sampleRec.height *= d->optimize_resize;

        orig_width = MagickGetImageWidth(d->wand);
        orig_height = MagickGetImageHeight(d->wand);

        if(sampleRec.width < orig_width && sampleRec.height < orig_height) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Sampling image down to %dx%d before resizing.", sampleRec.width, sampleRec.height);
            MAGICK_CHECK(MagickSampleImage(d->wand, sampleRec.width, sampleRec.height), d);
        }
    }

    MAGICK_CHECK(MagickScaleImage(d->wand, rec.width, rec.height), d);

    return DIMS_SUCCESS;
}

apr_status_t
dims_sharpen_operation (dims_request_rec *d, char *args, char **err) {
    MagickStatusType flags;
    GeometryInfo geometry;

    flags = ParseGeometry(args, &geometry);
    if ((flags & SigmaValue) == 0) {
        geometry.sigma=1.0;
    }

    MAGICK_CHECK(MagickSharpenImage(d->wand, geometry.rho, geometry.sigma), d);

    return DIMS_SUCCESS;
}

apr_status_t
dims_thumbnail_operation (dims_request_rec *d, char *args, char **err) {
    MagickStatusType flags;
    RectangleInfo rec;
    char *resize_args = apr_psprintf(d->pool, "%s^", args);

    flags = ParseSizeGeometry(GetImageFromMagickWand(d->wand), resize_args, &rec);
    if(!(flags & AllValues)) {
        *err = "Parsing thumbnail (resize) geometry failed";
        return DIMS_FAILURE;
    }

    char *format = MagickGetImageFormat(d->wand);
    if (strcmp(format, "JPEG") == 0) {
        double factors[3] = { 2.0, 1.0, 1.0 };
        MAGICK_CHECK(MagickSetSamplingFactors(d->wand, 3, &factors), d);
    }

    if (d->optimize_resize) {
        size_t orig_width;
        size_t orig_height;

        RectangleInfo sampleRec = rec;
        sampleRec.width *= d->optimize_resize;
        sampleRec.height *= d->optimize_resize;

        orig_width = MagickGetImageWidth(d->wand);
        orig_height = MagickGetImageHeight(d->wand);

        if(sampleRec.width < orig_width && sampleRec.height < orig_height) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "Sampling image down to %dx%d before resizing.", sampleRec.width, sampleRec.height);
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

apr_status_t
dims_crop_operation (dims_request_rec *d, char *args, char **err) {
    MagickStatusType flags;
    RectangleInfo rec;
    ExceptionInfo ex_info;

    flags = ParseGravityGeometry(GetImageFromMagickWand(d->wand), args, &rec, &ex_info);
    if(!(flags & AllValues)) {
        *err = "Parsing crop geometry failed";
        return DIMS_FAILURE;
    }

    MAGICK_CHECK(MagickCropImage(d->wand, rec.width, rec.height, rec.x, rec.y), d);
    MAGICK_CHECK(MagickSetImagePage(d->wand, rec.width, rec.height, rec.x, rec.y), d);

    return DIMS_SUCCESS;
}

apr_status_t
dims_format_operation (dims_request_rec *d, char *args, char **err) {
    MAGICK_CHECK(MagickSetImageFormat(d->wand, args), d);
    return DIMS_SUCCESS;
}

apr_status_t
dims_quality_operation (dims_request_rec *d, char *args, char **err) {
    int quality = apr_strtoi64(args, NULL, 0);
    int existing_quality = MagickGetImageCompressionQuality(d->wand);

    if(quality < existing_quality) {
        MAGICK_CHECK(MagickSetImageCompressionQuality(d->wand, quality), d);
    }
    return DIMS_SUCCESS;
}

apr_status_t
dims_brightness_operation (dims_request_rec *d, char *args, char **err) {
    MagickStatusType flags;
    GeometryInfo geometry;

    flags = ParseGeometry(args, &geometry);

    MAGICK_CHECK(MagickBrightnessContrastImage(d->wand,
            geometry.rho, geometry.sigma), d);

    return DIMS_SUCCESS;
}

apr_status_t
dims_flipflop_operation (dims_request_rec *d, char *args, char **err) {
    if(args != NULL) {
        if(strcmp(args, "horizontal") == 0) {
            MAGICK_CHECK(MagickFlopImage(d->wand), d);
        } else if (strcmp(args, "vertical") == 0) {
            MAGICK_CHECK(MagickFlipImage(d->wand), d);
        }
    }

    return DIMS_SUCCESS;
}

apr_status_t
dims_sepia_operation (dims_request_rec *d, char *args, char **err) {
    double threshold = atof(args);

    MAGICK_CHECK(MagickSepiaToneImage(d->wand, threshold * QuantumRange), d);

    return DIMS_SUCCESS;
}

apr_status_t
dims_grayscale_operation (dims_request_rec *d, char *args, char **err) {

    if(args != NULL) {
        if(strcmp(args, "true") == 0) {
            MAGICK_CHECK(MagickSetImageColorspace(d->wand, GRAYColorspace), d);
        }
    }

    return DIMS_SUCCESS;
}

apr_status_t
dims_autolevel_operation (dims_request_rec *d, char *args, char **err) {

    if(args != NULL) {
        if(strcmp(args, "true") == 0) {
            MAGICK_CHECK(MagickAutoLevelImage(d->wand), d);
        }
    }

    return DIMS_SUCCESS;
}

apr_status_t
dims_invert_operation (dims_request_rec *d, char *args, char **err) {

    if(args != NULL) {
        if(strcmp(args, "true") == 0) {
            MAGICK_CHECK(MagickNegateImage(d->wand, MagickFalse), d);
        }
    }

    return DIMS_SUCCESS;
}

apr_status_t
dims_rotate_operation (dims_request_rec *d, char *args, char **err) {
    double degrees = atof(args);

    PixelWand *pxWand = NewPixelWand();
    MAGICK_CHECK(MagickRotateImage(d->wand, pxWand, degrees), d);
    DestroyPixelWand(pxWand);

    return DIMS_SUCCESS;
}

/*
 * Watermark expects (in order) index, opacity, size of overlay in respect to source image (percentage), and region.
 * Eg. /watermark/1,.2,.5,se
 * This would give us a watermark of index 1, 0.2 opacity, 50% of the source image's size, in the southeast region.
 * The index is used to map to the appropriate overlay parameter. In the example above, we'll use the parameter overlay1.
 */
apr_status_t
dims_watermark_operation (dims_request_rec *d, char *args, char **err) {
    char *index;
    float opacity;
    double size;
    GravityType gravity;

    char *token = strtok(args, ",");

    if (token) {
        index = token;
    }

    token = strtok(NULL, ",");

    if (token) {
        opacity = atof(token);
    }

    token = strtok(NULL, ",");

    if (token) {
        size = atof(token);
    }

    token = strtok(NULL, ",");

    if (token) {
        if (strcmp(token, "nw") == 0) {
            gravity = NorthWestGravity;

        } else if (strcmp(token, "n") == 0) {
            gravity = NorthGravity;

        } else if (strcmp(token, "ne") == 0) {
            gravity = NorthEastGravity;

        } else if (strcmp(token, "w") == 0) {
            gravity = WestGravity;

        } else if (strcmp(token, "c") == 0) {
            gravity = CenterGravity;

        } else if (strcmp(token, "e") == 0) {
            gravity = EastGravity;

        } else if (strcmp(token, "sw") == 0) {
            gravity = SouthWestGravity;

        } else if (strcmp(token, "s") == 0) {
            gravity = SouthGravity;

        } else if (strcmp(token, "se") == 0) {
            gravity = SouthEastGravity;
        }
    }

    char *overlay_url;

    if (d->r->args) {
        const size_t args_len = strlen(d->r->args) + 1;
        char *args_copy = malloc(args_len);
        strncpy(args_copy, d->r->args, args_len);
        char *token;
        char *strtokstate;
        token = apr_strtok(args_copy, "&", &strtokstate);

        char *param = malloc(strlen(index) + 9);
        strcpy(param, "overlay");
        strcat(param, index);
        strcat(param, "=");

        while (token) {
            if (strncmp(token, param, 4) == 0) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "ARG: %s", token);
                overlay_url = apr_pstrdup(d->r->pool, token + strlen(index) + 8);
                ap_unescape_url(overlay_url);
            }
            token = apr_strtok(NULL, "&", &strtokstate);
        }

        free(param);
    }

    // New wand for overlay image.
    MagickWand *overlay_wand = NewMagickWand();
    MagickReadImage(overlay_wand, overlay_url);

    // Opacity.
    PixelWand *pColorize = NewPixelWand();
    PixelWand *pGivenAlpha = NewPixelWand();
    PixelSetColor(pColorize, "transparent");
    PixelSetAlpha(pGivenAlpha, opacity);
    MagickColorizeImage(overlay_wand, pColorize, pGivenAlpha);

    // Resize based on percentage.
    MAGICK_CHECK(MagickScaleImage(overlay_wand, MagickGetImageWidth(d->wand) * size, MagickGetImageHeight(d->wand) * size), d);

    // Apply overlay.
    MAGICK_CHECK(MagickCompositeImageGravity(d->wand, overlay_wand, OverCompositeOp, gravity), d);

    return DIMS_SUCCESS;
}


/**
 * Legacy API support.
 */
apr_status_t
dims_legacy_crop_operation (dims_request_rec *d, char *args, char **err) {
    MagickStatusType flags;
    RectangleInfo rec;
    ExceptionInfo ex_info;
    long width, height;
    int x, y;

    flags = ParseGravityGeometry(GetImageFromMagickWand(d->wand), args, &rec, &ex_info);

    if(!(flags & AllValues)) {
        *err = "Parsing crop geometry failed";
        return DIMS_FAILURE;
    }

    width = MagickGetImageWidth(d->wand);
    height = MagickGetImageHeight(d->wand);
    x = (width / 2) - (rec.width / 2);
    y = (height / 2) - (rec.height / 2);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
        "legacy_crop will crop to %ldx%ld+%d+%d", 
        rec.width, rec.height, x, y);

    MAGICK_CHECK(MagickCropImage(d->wand, rec.width, rec.height, x, y), d);

    return DIMS_SUCCESS;
}

apr_status_t
dims_legacy_thumbnail_operation (dims_request_rec *d, char *args, char **err) {
    MagickStatusType flags;
    RectangleInfo rec;
    long width, height;
    int x, y;
    char *resize_args = apr_psprintf(d->pool, "%s^", args);

    flags = ParseSizeGeometry(GetImageFromMagickWand(d->wand), resize_args, &rec);
    if(!(flags & AllValues)) {
        *err = "Parsing thumbnail (resize) geometry failed";
        return DIMS_FAILURE;
    }

    char *format = MagickGetImageFormat(d->wand);
    if (strcmp(format, "JPEG") == 0) {
        double factors[3] = { 2.0, 1.0, 1.0 };
        MAGICK_CHECK(MagickSetSamplingFactors(d->wand, 3, &factors), d);
    }

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

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
        "legacy_thumbnail will crop to %ldx%ld+%d+%d", rec.width, rec.height, x, y);

    MAGICK_CHECK(MagickCropImage(d->wand, rec.width, rec.height, x, y), d);

    return DIMS_SUCCESS;
}

