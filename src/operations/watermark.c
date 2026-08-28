/*
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "operations.h"
#include "../curl.h"
#include "../netguard.h"
#include "../url.h"

#include <openssl/sha.h>
#include <paths.h>
#include <unistd.h>

typedef struct DimsGravity {
    const char *name;
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
 * Watermark expects (in order) opacity, size of overlay in respect to source image (percentage), and region.
 * Eg. /watermark/.2,.5,se
 * This would give us a watermark of 0.2 opacity, 50% of the source image's size, in the southeast region.
 * This also expects the overlay image url as an additional query parameter.
 */
apr_status_t
dims_watermark_operation (dims_request_rec *d, char *args, const char **err) {
    MagickWand *overlay_wand = NewMagickWand();
    char *overlay_url = NULL;

    if (d->r->args) {
        const size_t args_len = strlen(d->r->args) + 1;
        char *args = apr_pstrndup(d->r->pool, d->r->args, args_len);
        char *token;
        char *strtokstate = NULL;

        token = apr_strtok(args, "&", &strtokstate);
        while (token) {
            const char *value = dims_param_value(token, "overlay=");

            if (value != NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, d->r, "ARG: %s", token);
                overlay_url = apr_pstrdup(d->r->pool, value);
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

    /* Hash the overlay basename. sizeof on a pointer would hash eight bytes
     * of the address instead, so two overlays sharing a prefix would share a
     * cache entry and the address would change the key between runs. */
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *) filename, strlen(filename), hash);

    // Convert to hex.
    char hex[SHA_DIGEST_LENGTH * 2 + 1];
    if (apr_escape_hex(hex, hash, SHA_DIGEST_LENGTH, 0, NULL) != APR_SUCCESS) {
        return DIMS_FAILURE;
    }

    // 1. Check TMPDIR environment variable.
    // 2. Check P_tmpdir macro from stdio.h.
    // 3. Check _PATH_TMP macro from paths.h.
    // 4. Use /tmp/.
    const char *tmp_dir = getenv("TMPDIR");

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
        if (MagickReadImage(overlay_wand, finfo.fname) == MagickFalse) {
            *err = "Unable to read the cached overlay image!";
            return DIMS_FAILURE;
        }

    // Write to disk.
    } else {
        dims_image_data_t image_data;
        dims_allowlist_mode mode = d->config->allowlist_signed
                ? DIMS_ALLOWLIST_ENFORCE : DIMS_ALLOWLIST_LOG;

        /* The overlay URL comes from the query string and no signature covers
         * it, so it reaches the same guard the source image reaches. */
        if (dims_validate_image_url(d, overlay_url, mode) != DIMS_NET_OK) {
            *err = "Refused to fetch the overlay image!";
            return DIMS_FAILURE;
        }

        /* A failed transfer leaves data NULL and used zero. */
        if (dims_get_image_data(d, overlay_url, &image_data, mode) != CURLE_OK) {
            if (image_data.data) {
                free(image_data.data);
            }

            *err = "Unable to fetch overlay image from overlay URL!";
            return DIMS_FAILURE;
        }

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

    /* Each is read below whether or not its token was present, so each needs
     * a value. A zero width and height make the scale fail. */
    float opacity = 0.0f;
    double size = 0.0;
    GravityType gravity = UndefinedGravity;

    /* apr_strtok keeps its state here. strtok keeps it in one static
     * location shared by every request in the process. */
    char *strtokstate = NULL;
    char *token = apr_strtok(args, ",", &strtokstate);

    if (token) {
        opacity = atof(token);
    }

    token = apr_strtok(NULL, ",", &strtokstate);

    if (token) {
        size = atof(token);
    }

    token = apr_strtok(NULL, ",", &strtokstate);
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

    /*
     * Reduce the overlay's opacity.
     *
     * Multiply the alpha channel, never replace it. MagickSetImageAlpha sets
     * every pixel to one alpha, including the transparent background, which
     * puts a translucent rectangle behind the overlay.
     */
    MagickSetImageAlphaChannel(overlay_wand, OnAlphaChannel);
    {
        ChannelType previous = MagickSetImageChannelMask(overlay_wand, AlphaChannel);

        MagickEvaluateImage(overlay_wand, MultiplyEvaluateOperator, opacity);
        MagickSetImageChannelMask(overlay_wand, previous);
    }
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

    return DIMS_SUCCESS;
}
