
#include <apr.h>
#include <httpd.h>

#include "mod_dims.h"
#include "mod_dims_ops.h"
#include "curl.h"
#include "module.h"

apr_shm_t *shm;

typedef struct operations {
    char *name;
    dims_operation_func *func;
} operations;

static operations ops[] = {
    {"strip", dims_strip_operation},
    {"resize", dims_resize_operation},
    {"crop", dims_crop_operation},
    {"thumbnail", dims_thumbnail_operation},
    {"legacy_thumbnail", dims_legacy_thumbnail_operation},
    {"legacy_crop", dims_legacy_crop_operation},
    {"quality", dims_quality_operation},
    {"sharpen", dims_sharpen_operation},
    {"format", dims_format_operation},
    {"brightness", dims_brightness_operation},
    {"flipflop", dims_flipflop_operation},
    {"sepia", dims_sepia_operation},
    {"grayscale", dims_grayscale_operation},
    {"autolevel", dims_autolevel_operation},
    {"rotate", dims_rotate_operation},
    {"invert", dims_invert_operation},
    {"watermark", dims_watermark_operation},
    NULL
};

int
dims_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t* ptemp, server_rec *s)
{
    dims_config_rec *config = (dims_config_rec *) 
            ap_get_module_config(s->module_config, &dims_module);
    apr_status_t status;
    apr_size_t retsize;

    ap_add_version_component(p, "mod_dims/" MODULE_VERSION);

    MagickWandGenesis();
    MagickSetResourceLimit(AreaResource, config->area_size);
    MagickSetResourceLimit(DiskResource, config->disk_size);
    MagickSetResourceLimit(MemoryResource, config->memory_size);
    MagickSetResourceLimit(MapResource, config->map_size);

    /* Init APR's atomic functions */
    status = apr_atomic_init(p);
    if (status != APR_SUCCESS)
        return HTTP_INTERNAL_SERVER_ERROR;

    /* Create shared memory block */
    status = apr_shm_create(&shm, sizeof(dims_stats_rec), NULL, p);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_dims : Error creating shm block\n");
        return status;
    }

    /* Check size of shared memory block */
    retsize = apr_shm_size_get(shm);
    if (retsize != sizeof(dims_stats_rec)) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_dims : Error allocating shared memory block\n");
        return status;
    }

    /* Init shm block */
    stats = apr_shm_baseaddr_get(shm);
    if (stats == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_dims : Error creating status block.\n");
        return status;
    }
    memset(stats, 0, retsize);

    if (retsize < sizeof(dims_stats_rec)) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                     "mod_dims : Not enough memory allocated!! Giving up");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    stats->success_count = 1;
    stats->failure_count = 0;
    stats->download_timeout_count = 0;
    stats->imagemagick_timeout_count = 0;

    return OK;
}

static apr_status_t
dims_child_cleanup(void *data)
{
    MagickWandTerminus();

    return APR_SUCCESS;
}

void
dims_child_init(apr_pool_t *p, server_rec *s)
{
    dims_curl_init(p, s);

    MagickWandGenesis();
    apr_pool_cleanup_register(p, NULL, dims_child_cleanup, dims_child_cleanup);
}