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

#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <paths.h>

#include <magick/exception.h>

#define MAGICK_CHECK(func, rec) \
    do { \
        apr_status_t code = func; \
        if(rec->status == DIMS_IMAGEMAGICK_TIMEOUT) {\
            return DIMS_IMAGEMAGICK_TIMEOUT; \
        } else if(code == MagickFalse) {\
            return DIMS_FAILURE; \
        } \
    } while(0)

typedef struct DimsGravity {
    char *name;
    GravityType gravity;
} DimsGravity;

static DimsGravity gravities[] = {
    {"n", NorthGravity},
    {"ne", NorthEastGravity},
    {"nw", NorthWestGravity},
    {"s", SouthGravity},
    {"se", SouthEastGravity},
    {"sw", SouthWestGravity},
    {"w", WestGravity},
    {"e", EastGravity},
    {"c", CenterGravity},
    {NULL, CenterGravity}
};

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

apr_status_t
dims_crop_operation (dims_request_rec *d, char *args, char **err) {
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

    if(quality < existing_quality || existing_quality == 0) {
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
 * Watermark expects (in order) opacity, size of overlay in respect to source image (percentage), and region.
 * Eg. /watermark/.2,.5,se
 * This would give us a watermark of 0.2 opacity, 50% of the source image's size, in the southeast region.
 * This also expects the overlay image url as an additional query parameter.
 */
apr_status_t
dims_watermark_operation (dims_request_rec *d, char *args, char **err) {
    MagickWand *overlay_wand = NewMagickWand();
    char *overlay_url = NULL;

    if (d->r->args) {
        const size_t args_len = strlen(d->r->args) + 1;
        char *args = apr_pstrndup(d->r->pool, d->r->args, args_len);
        char *token;
        char *strtokstate;

        token = apr_strtok(args, "&", &strtokstate);
        while (token) {
            if (strncmp(token, "overlay=", 4) == 0) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "ARG: %s", token);
                overlay_url = apr_pstrdup(d->r->pool, token + 8);
                ap_unescape_url(overlay_url);
            }
            token = apr_strtok(NULL, "&", &strtokstate);
        }
    }

    if (overlay_url == NULL) {
        *err = "No overlay url!";
        return DIMS_FAILURE;
    }

    apr_finfo_t finfo;
    char *filename = strrchr(overlay_url, '/' );

    if (*filename == '/') {
        ++filename;
    }

    // Hash filename via SHA-1.
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(filename, sizeof(filename), hash);

    // Convert to hex.
    char hex[SHA_DIGEST_LENGTH * 2 + 1];
    if (apr_escape_hex(hex, hash, SHA_DIGEST_LENGTH, 0, NULL) != APR_SUCCESS) {
        return DIMS_FAILURE;
    }

    // 1. Check TMPDIR environment variable.
    // 2. Check P_tmpdir macro from stdio.h.
    // 3. Check _PATH_TMP macro from paths.h.
    // 4. Use /tmp/.
    char *tmp_dir = getenv("TMPDIR");

    if (tmp_dir == NULL) {
        #ifdef P_tmpdir
            tmp_dir = P_tmpdir;
        #else
            #ifdef _PATH_TMP
                tmp_dir = _PATH_TMP;
            #else
                tmp_dir = "/tmp/";
            #endif
        #endif
    }

    char *cache_dir = apr_pstrcat(d->pool, tmp_dir, "dims-cache/", NULL);

    if (apr_dir_make_recursive(cache_dir, APR_FPROT_UREAD | APR_FPROT_UWRITE | APR_FPROT_UEXECUTE, d->pool) != APR_SUCCESS) {
        *err = "Unable to create cache directory!";
        return DIMS_FAILURE;
    }

    filename = apr_pstrcat(d->pool, cache_dir, hex, NULL);

    // Try to read image from disk.
    if (apr_stat(&finfo, filename, APR_FINFO_SIZE, d->pool) == 0) {
        MagickReadImage(overlay_wand, finfo.fname);

    // Write to disk.
    } else {
        dims_image_data_t image_data;
        CURLcode code = dims_get_image_data(d, overlay_url, &image_data);

        if (MagickReadImageBlob(overlay_wand, image_data.data, image_data.used) == MagickFalse) {
            if (image_data.data) {
                free(image_data.data);
            }

            *err = "Unable to fetch overlay image from overlay URL!";
            return DIMS_FAILURE;
        }

        apr_file_t *cached_file;

        if (apr_file_open(&cached_file, filename, APR_FOPEN_CREATE | APR_FOPEN_WRITE, APR_FPROT_UREAD | APR_FPROT_UWRITE, d->pool) != APR_SUCCESS) {
            *err = "Unable to open overlay cache file!";
            return DIMS_FAILURE;
        }

        size_t bytes_to_write = image_data.used;
        if (apr_file_write(cached_file, image_data.data, &bytes_to_write) != APR_SUCCESS) {
            apr_file_close(cached_file);

            *err = "Unable to write overlay image to cache!";
            return DIMS_FAILURE;
        }

        apr_file_close(cached_file);

        free(image_data.data);
    }

    float opacity;
    double size;
    GravityType gravity;

    char *token = strtok(args, ",");

    if (token) {
        opacity = atof(token);
    }

    token = strtok(NULL, ",");

    if (token) {
        size = atof(token);
    }

    token = strtok(NULL, ",");
    if (token) {
        DimsGravity *gravity_ptr = gravities;
        while (gravity_ptr->name != NULL) {
            if (strcmp(token, gravity_ptr->name) == 0) {
                gravity = gravity_ptr->gravity;
                break;
            }

            gravity_ptr++;
        }
    }

    // Opacity.
    PixelWand *pColorize = NewPixelWand();
    PixelWand *pGivenAlpha = NewPixelWand();
    PixelSetColor(pColorize, "transparent");
    PixelSetAlpha(pGivenAlpha, opacity);
    MagickColorizeImage(overlay_wand, pColorize, pGivenAlpha);

    // Size.
    float original_width = (float) MagickGetImageWidth(d->wand);
    float original_height = (float) MagickGetImageHeight(d->wand);

    float overlay_width = (float) MagickGetImageWidth(overlay_wand);
    float overlay_height = (float) MagickGetImageHeight(overlay_wand);

    float final_width;
    float final_height;

    float largest_size;

    // Scale based on largest dimension.
    if (original_width > original_height) {
        largest_size = original_width * size;

    } else {
        largest_size = original_height * size;
    }

    if (overlay_width > overlay_height) {
        final_width = largest_size;
        final_height = largest_size / (overlay_width / overlay_height);

    } else if (overlay_width < overlay_height) {
        final_width = largest_size / (overlay_height / overlay_width);
        final_height = largest_size;

    } else {
        final_width = largest_size;
        final_height = largest_size;
    }

    MAGICK_CHECK(MagickScaleImage(overlay_wand, final_width, final_height), d);

    // Apply overlay.
    MAGICK_CHECK(MagickCompositeImageGravity(d->wand, overlay_wand, OverCompositeOp, gravity), d);

    DestroyMagickWand(overlay_wand);
    DestroyPixelWand(pColorize);
    DestroyPixelWand(pGivenAlpha);

    return DIMS_SUCCESS;
}


/**
 * Legacy API support.
 */
apr_status_t
dims_legacy_crop_operation (dims_request_rec *d, char *args, char **err) {
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

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, 
        "legacy_thumbnail will crop to %ldx%ld+%d+%d", rec.width, rec.height, x, y);

    MAGICK_CHECK(MagickCropImage(d->wand, rec.width, rec.height, x, y), d);

    return DIMS_SUCCESS;
}

