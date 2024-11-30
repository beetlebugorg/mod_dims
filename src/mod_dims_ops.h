
#ifndef _MOD_DIMS_OPS_H
#define _MOD_DIMS_OPS_H

#include "request.h"

typedef apr_status_t(dims_operation_func) (dims_request_rec *, char *args, char **err);

typedef struct {
    char *name;
    dims_operation_func *func;
} operations_rec;

dims_operation_func 
    dims_strip_operation,
    dims_resize_operation,
    dims_crop_operation,
    dims_thumbnail_operation,
    dims_sharpen_operation,
    dims_quality_operation,
    dims_format_operation,
    dims_legacy_thumbnail_operation,
    dims_smart_crop_operation,
    dims_brightness_operation,
    dims_flipflop_operation,
    dims_sepia_operation,
    dims_grayscale_operation,
    dims_autolevel_operation,
    dims_rotate_operation,
    dims_invert_operation,
    dims_watermark_operation,
    dims_legacy_crop_operation;

dims_operation_func *dims_operation_lookup(char *name);

#endif