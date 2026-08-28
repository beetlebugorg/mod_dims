/*
 * Starting and stopping the module.
 *
 * httpd calls into this file three times: once to build the server
 * configuration, once per process after the fork, and once per request. Every
 * global the module keeps is created here.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module.h"
#include "configuration.h"
#include "curl.h"
#include "handler.h"
#include "netguard.h"
#include "pipeline.h"
#include "profile.h"
#include "status.h"

#include <MagickWand/MagickWand.h>
#include <curl/curl.h>

/* httpd runs post_config twice. This marks the pass that counts. */
#define DIMS_POST_CONFIG_KEY "dims_post_config"

static int
dims_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t* ptemp, server_rec *s)
{
    apr_status_t status;
    apr_size_t retsize;
    void *first_pass = NULL;

    /*
     * httpd runs post_config twice, and clears the first pass's pool
     * afterwards. Skip that pass, so the shared memory is created once
     * against a pool that lives as long as the server.
     */
    apr_pool_userdata_get(&first_pass, DIMS_POST_CONFIG_KEY, s->process->pool);
    if (first_pass == NULL) {
        apr_pool_userdata_set((const void *) 1, DIMS_POST_CONFIG_KEY,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    ap_add_version_component(p, "mod_dims/" DIMS_VERSION);

    /* Say which tiers of the network guard the operator left permissive, on
     * every server, so the setting is visible without reading the config. */
    {
        server_rec *server;

        for (server = s; server != NULL; server = server->next) {
            dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
                    server->module_config, &dims_module);

            if (config != NULL) {
                dims_netguard_log_configuration(server, config);
            }
        }
    }

    /*
     * ImageMagick starts in the child, never here. A worker that inherits its
     * semaphores and cache state across the fork segfaults on its first
     * request. The resource limits go with it, being per process. See
     * dims_child_init.
     */

    ops = apr_hash_make(p);
    apr_hash_set(ops, "strip", APR_HASH_KEY_STRING, dims_strip_operation);
    apr_hash_set(ops, "resize", APR_HASH_KEY_STRING, dims_resize_operation);
    apr_hash_set(ops, "crop", APR_HASH_KEY_STRING, dims_crop_operation);
    apr_hash_set(ops, "thumbnail", APR_HASH_KEY_STRING, dims_thumbnail_operation);
    apr_hash_set(ops, "legacy_thumbnail", APR_HASH_KEY_STRING, dims_legacy_thumbnail_operation);
    apr_hash_set(ops, "legacy_crop", APR_HASH_KEY_STRING, dims_legacy_crop_operation);
    apr_hash_set(ops, "quality", APR_HASH_KEY_STRING, dims_quality_operation);
    apr_hash_set(ops, "sharpen", APR_HASH_KEY_STRING, dims_sharpen_operation);
    apr_hash_set(ops, "format", APR_HASH_KEY_STRING, dims_format_operation);
    apr_hash_set(ops, "brightness", APR_HASH_KEY_STRING, dims_brightness_operation);
    apr_hash_set(ops, "flipflop", APR_HASH_KEY_STRING, dims_flipflop_operation);
    apr_hash_set(ops, "sepia", APR_HASH_KEY_STRING, dims_sepia_operation);
    apr_hash_set(ops, "grayscale", APR_HASH_KEY_STRING, dims_grayscale_operation);
    apr_hash_set(ops, "autolevel", APR_HASH_KEY_STRING, dims_autolevel_operation);
    apr_hash_set(ops, "rotate", APR_HASH_KEY_STRING, dims_rotate_operation);
    apr_hash_set(ops, "invert", APR_HASH_KEY_STRING, dims_invert_operation);
    apr_hash_set(ops, "watermark", APR_HASH_KEY_STRING, dims_watermark_operation);

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



apr_status_t
dims_child_cleanup(void *data)
{
    dims_curl_rec *locks = (dims_curl_rec *) data;

    curl_share_cleanup(locks->share);
    curl_global_cleanup();

    apr_thread_mutex_destroy(locks->share_mutex);
    apr_thread_mutex_destroy(locks->dns_mutex);

    apr_pool_userdata_set(NULL, DIMS_CURL_SHARED_KEY, NULL,
            locks->s->process->pool);

    MagickWandTerminus();

    return APR_SUCCESS;
}

void
dims_child_init(apr_pool_t *p, server_rec *s)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            s->module_config, &dims_module);

    MagickWandGenesis();

    dims_profiles_load(p, s, config->profile_dir);

    /* Every limit is per process, so the total a host can use is this
     * multiplied by the number of workers. */
    MagickSetResourceLimit(AreaResource, config->area_size);
    MagickSetResourceLimit(DiskResource, config->disk_size);
    MagickSetResourceLimit(MemoryResource, config->memory_size);
    MagickSetResourceLimit(MapResource, config->map_size);

    /* One thread per operation. ImageMagick's OpenMP otherwise starts a thread
     * per core for each request, so the MPM worker count multiplies into
     * hundreds of threads. The MPM provides the concurrency. */
    MagickSetResourceLimit(ThreadResource, 1);
    curl_global_init(CURL_GLOBAL_ALL);

    dims_curl_rec *locks =
            (dims_curl_rec *) apr_pcalloc(p, sizeof(dims_curl_rec));

    locks->s = s;
    locks->share = curl_share_init();

    apr_thread_mutex_create(&locks->share_mutex, APR_THREAD_MUTEX_DEFAULT, p);
    apr_thread_mutex_create(&locks->dns_mutex, APR_THREAD_MUTEX_DEFAULT, p);

    curl_share_setopt(locks->share, CURLSHOPT_LOCKFUNC, lock_share);
    curl_share_setopt(locks->share, CURLSHOPT_UNLOCKFUNC, unlock_share);
    curl_share_setopt(locks->share, CURLSHOPT_USERDATA, (void *) locks);
    curl_share_setopt(locks->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);

    /* Share the TLS session cache too, so a new connection can resume a session
     * and skip the full handshake. Every fetch still opens its own socket, so
     * the address guard runs on each. */
    curl_share_setopt(locks->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);

    /* We have to associate our handle/locks with the process->pool otherwise
     * we won't be able to get at it from the remote_fetch_image function.  This
     * pool doesn't seem to go away when the child process goes away so we
     * have to register the clean up method below.
     */
    apr_pool_userdata_set(locks, DIMS_CURL_SHARED_KEY, NULL, s->process->pool);

    /* Register cleanup with the 'p' pool so we can clean up the locks and
     * shared curl handle when this process dies.
     */
    apr_pool_cleanup_register(p, locks, dims_child_cleanup, dims_child_cleanup);
}

static void
dims_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(dims_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(dims_child_init, NULL, NULL,APR_HOOK_MIDDLE);
    ap_hook_handler(dims_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA dims_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                   /* dir config creater */
    NULL,                   /* dir merger --- default is to override */
    dims_create_config,     /* server config */
    NULL,                   /* merge server config */
    dims_directives,        /* command apr_table_t */
    dims_register_hooks,    /* register hooks */
    0                       /* flags */
};
