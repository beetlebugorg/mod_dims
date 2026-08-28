/*
 * The server configuration and the directives that fill it.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "configuration.h"

#include <ctype.h>
#include <strings.h>
#include <limits.h>

void *
dims_create_config(apr_pool_t *p, server_rec *s)
{
    dims_config_rec *config;

    config = (dims_config_rec *) apr_pcalloc(p, sizeof(dims_config_rec));
    config->whitelist = apr_table_make(p, 5);
    config->clients = apr_hash_make(p);
    config->ignore_default_output_format = apr_table_make(p, 3);

    config->download_timeout = 3000;
    config->imagemagick_timeout = 3000;

    config->no_image_url = NULL;
    config->no_image_expire = 60;
    config->default_image_prefix = NULL;

    config->default_expire = 86400;

    config->strip_metadata = 1;
    config->optimize_resize = 0;
    config->disable_encoded_fetch = 0;
    config->default_output_format = NULL;

    config->area_size = 128 * 1024 * 1024;         //  128mb max.
    config->memory_size = 512 * 1024 * 1024;       //  512mb max.
    config->map_size = 1024 * 1024 * 1024;         // 1024mb max.
    config->disk_size = 2048UL * 1024UL * 1024UL;  // 2048mb max.

    config->curl_queue_size = 10;
    config->cache_dir = NULL;
    config->secret_key = apr_pstrdup(p,"m0d1ms");
    config->encryption_algorithm = "AES/ECB/PKCS5Padding";
    config->max_expiry_period= 0; // never expire

    /*
     * Both defaults reproduce what the module did before the guard existed.
     * The tier that no deployment depends on, loopback and link local, is
     * refused whatever these hold.
     */
    config->allow_private_addresses = 1;
    config->allowlist_signed = 0;
    config->origin_status_mode = DIMS_ORIGIN_STATUS_FORWARD;
    config->status_verbose = 1;

    /* The cache holds fetched overlays, and an evicted one is fetched again,
     * so a bound costs a caller nothing. */
    config->overlay_cache_max_entries = 1024;
    config->overlay_cache_max_age = 86400;
    config->animated_mode = DIMS_ANIMATED_PASSTHROUGH;

    return (void *) config;
}

static const char *
dims_config_set_whitelist(cmd_parms *cmd, void *d, int argc, char *const argv[])
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, 
            &dims_module);
    int i;

    for(i = 0; i < argc; i++) {
        char *hostname = argv[i];

        /* Remove glob character and '.' if they're on the string and set
         * the value in the hash to glob.  
         */
        if(hostname[0] == '*') {
            if(*++hostname == '.') {
                hostname++;
            }

            apr_table_setn(config->whitelist, hostname, "glob");
        } else {
            apr_table_setn(config->whitelist, argv[i], "exact");
        }
    }

    return NULL;
}

static const char *
dims_config_set_ignore_default_output_format(cmd_parms *cmd, void *d, int argc, char *const argv[])
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config,
            &dims_module);
    int i;

    for(i = 0; i < argc; i++) {
        char *format = argv[i];
        char *s = format;
        while (*s) { *s = toupper(*s); s++; }

        apr_table_setn(config->ignore_default_output_format, format, "1");
    }
    return NULL;
}

static const char *
dims_config_set_default_expire(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->default_expire = atol(arg);
    return NULL;
}

static const char *
dims_config_set_no_image_expire(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->no_image_expire = atol(arg);
    return NULL;
}

static const char *
dims_config_set_download_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->download_timeout = atol(arg);
    return NULL;
}

static const char *
dims_config_set_imagemagick_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->imagemagick_timeout = atol(arg);
    return NULL;
}

static const char *
dims_config_set_strip_metadata(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    // The default is 1, so anything other than "false" will use the default
    if(strcmp(arg, "false") == 0) {
        config->strip_metadata = 0;
    }
    else {
        config->strip_metadata = 1;
    }
    return NULL;
}

static const char *
dims_config_set_include_disposition(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    if(strcmp(arg, "true") == 0) {
        config->include_disposition = 1;
    }
    else {
        config->include_disposition = 0;
    }
    return NULL;
}

static const char *
dims_config_set_optimize_resize(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->optimize_resize = atof(arg);
    return NULL;
}

static const char *
dims_config_set_encoded_fetch(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->disable_encoded_fetch = atoi(arg);
    return NULL;
}

static const char *
dims_config_set_encryption_algorithm(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->encryption_algorithm = (char *) arg;
    return NULL;
}

static const char *
dims_config_set_default_output_format(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    char *output_format = (char *) arg;
    char *s = output_format;
    while (*s) { *s = toupper(*s); s++; }
    config->default_output_format = output_format;
    return NULL;
}

static const char *
dims_config_set_user_agent_override(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    char *user_agent = (char *) arg;
    config->user_agent_override = user_agent;
    return NULL;
}

static const char *
dims_config_set_user_agent_enabled(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    if(strcmp(arg, "true") == 0) {
        config->user_agent_enabled = 1;
    }
    else {
        config->user_agent_enabled = 0;
    }
    return NULL;
}

static const char *
dims_config_set_client(cmd_parms *cmd, void *d, int argc, char *const argv[])
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);

    dims_client_config_rec *client_config = NULL;

    if(argc == 0) {
        return NULL;
    }

    if(argc >= 1) {
        client_config = (dims_client_config_rec *) 
                apr_pcalloc(cmd->pool, 
                            sizeof(dims_client_config_rec));

        client_config->no_image_url = NULL;
        client_config->cache_control_max_age = config->default_expire;
        client_config->edge_control_downstream_ttl = -1;
        client_config->trust_src = 0;
        client_config->min_src_cache_control = -1;
        client_config->max_src_cache_control = -1;

        /* Each case falls into the next on purpose: the directive takes a
         * variable number of arguments, and a shorter list means the later
         * ones keep the defaults set above. */
        switch(argc) {
            case 8:
                if(strcmp(argv[7], "-") != 0) {
                    client_config->secret_key = argv[7];
                } else {
                    client_config->secret_key = NULL;
                }
                /* fall through */
            case 7:
                if(strcmp(argv[6], "-") != 0) {
                    if(atoi(argv[6]) <= 0 && strcmp(argv[6], "0") != 0) {
                        // erroneous value
                        client_config->max_src_cache_control = -2;
                    }
                    else {
                        client_config->max_src_cache_control = atoi(argv[6]);
                    }
                }
                /* fall through */
            case 6:
                if(strcmp(argv[5], "-") != 0) {
                    if(atoi(argv[5]) <= 0 && strcmp(argv[5], "0") != 0) {
                        // erroneous value
                        client_config->min_src_cache_control = -2;
                    }
                    else {
                        client_config->min_src_cache_control = atoi(argv[5]);
                    }
                }
                /* fall through */
            case 5:
                if(strcmp(argv[4], "trust") == 0) {
                    client_config->trust_src = 1;
                }
                /* fall through */
            case 4:
                if(strcmp(argv[3], "-") != 0) {
                    client_config->edge_control_downstream_ttl = atoi(argv[3]);
                }
                /* fall through */
            case 3:
                if(strcmp(argv[2], "-") != 0) {
                    client_config->cache_control_max_age = atoi(argv[2]);
                }
                /* fall through */
            case 2:
                if(strcmp(argv[1], "-") != 0) {
                    client_config->no_image_url = argv[1];
                }
                /* fall through */
            case 1:
                client_config->id = argv[0];
        }
    }

    apr_hash_set(config->clients, argv[0], APR_HASH_KEY_STRING, client_config);

    return NULL;
}

static const char *
dims_config_set_max_source_bytes(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    char *end = NULL;
    apr_int64_t value = apr_strtoi64(arg, &end, 10);

    if (end == arg || *end != '\0' || value < 0) {
        return "DimsMaxSourceBytes must be a whole number of bytes, or 0 for no limit";
    }

    config->max_source_bytes = (size_t) value;
    return NULL;
}

static const char *
dims_config_set_allow_private_addresses(cmd_parms *cmd, void *dummy, int arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->allow_private_addresses = arg;
    return NULL;
}

static const char *
dims_config_set_allowlist_signed(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);

    if (strcasecmp(arg, "log") == 0) {
        config->allowlist_signed = 0;
    } else if (strcasecmp(arg, "enforce") == 0) {
        config->allowlist_signed = 1;
    } else {
        return "DimsAllowlistSigned must be log or enforce";
    }

    return NULL;
}

static const char *
dims_config_set_animated_images(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);

    if (strcasecmp(arg, "passthrough") == 0) {
        config->animated_mode = DIMS_ANIMATED_PASSTHROUGH;
    } else if (strcasecmp(arg, "transform") == 0) {
        config->animated_mode = DIMS_ANIMATED_TRANSFORM;
    } else {
        return "DimsAnimatedImages must be passthrough or transform";
    }

    return NULL;
}

static const char *
dims_config_set_overlay_cache_max_entries(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    char *end = NULL;
    long value = strtol(arg, &end, 10);

    if (end == arg || *end != '\0' || value < 0 || value > INT_MAX) {
        return "DimsOverlayCacheMaxEntries must be a count, or 0 for no limit";
    }

    config->overlay_cache_max_entries = (int) value;
    return NULL;
}

static const char *
dims_config_set_overlay_cache_max_age(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    char *end = NULL;
    long value = strtol(arg, &end, 10);

    if (end == arg || *end != '\0' || value < 0) {
        return "DimsOverlayCacheMaxAge must be a number of seconds, or 0 to "
               "never expire";
    }

    config->overlay_cache_max_age = value;
    return NULL;
}

static const char *
dims_config_set_origin_status_mode(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);

    if (strcasecmp(arg, "forward") == 0) {
        config->origin_status_mode = DIMS_ORIGIN_STATUS_FORWARD;
    } else if (strcasecmp(arg, "map") == 0) {
        config->origin_status_mode = DIMS_ORIGIN_STATUS_MAP;
    } else {
        return "DimsOriginStatusMode must be forward or map";
    }

    return NULL;
}

static const char *
dims_config_set_status_verbose(cmd_parms *cmd, void *dummy, int arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->status_verbose = arg;
    return NULL;
}

static const char *
dims_config_set_no_image_url(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->no_image_url = (char *) arg;
    return NULL;
}

static const char *
dims_config_set_image_prefix(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->default_image_prefix = (char *) arg;

    if (strncmp(config->default_image_prefix, "https://", 8) != 0 &&
        strncmp(config->default_image_prefix, "http://", 7) != 0) {
        return "DimsDefaultImagePrefix must start with 'https://' or 'http://'";
    }

    return NULL;
}

static const char *
dims_config_set_imagemagick_disk_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->disk_size = atol(arg) * 1024 * 1024;
    
    return NULL;
}
static const char *
dims_config_set_secretkeyExpiryPeriod(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->max_expiry_period = atol(arg);
    return NULL;
}
static const char *
dims_config_set_imagemagick_area_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->area_size = atol(arg) * 1024 * 1024;
    return NULL;
}

static const char *
dims_config_set_imagemagick_map_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->map_size = atol(arg) * 1024 * 1024;
    return NULL;
}

static const char *
dims_config_set_imagemagick_memory_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->memory_size = atol(arg) * 1024 * 1024;
    return NULL;
}

const command_rec dims_directives[] =
{
    AP_INIT_TAKE_ARGV("DimsAddWhitelist",
                      dims_config_set_whitelist, NULL, RSRC_CONF,
                      "Add whitelist hostname for DIMS URL requests."),
    AP_INIT_TAKE_ARGV("DimsAddClient",
                      dims_config_set_client, NULL, RSRC_CONF,
                      "Add a client with optional no image url, max-age and downstream-ttl settings."),
    AP_INIT_TAKE_ARGV("DimsIgnoreDefaultOutputFormat",
                      dims_config_set_ignore_default_output_format, NULL, RSRC_CONF,
                      "Add input formats that shouldn't be converted to the default output format."),
    AP_INIT_TAKE1("DimsDefaultImageURL",
                  dims_config_set_no_image_url, NULL, RSRC_CONF,
                  "Default image if processing fails or original image doesn't exist."),
    AP_INIT_TAKE1("DimsDefaultImagePrefix",
                  dims_config_set_image_prefix, NULL, RSRC_CONF,
                  "Default image prefix if URL is relative."),
    AP_INIT_TAKE1("DimsCacheExpire",
                  dims_config_set_default_expire, NULL, RSRC_CONF,
                  "Default expire time for Cache-Control/Expires/Edge-Control headers, in seconds."
                  "The default is 86400"),
    AP_INIT_TAKE1("DimsNoImageCacheExpire",
                  dims_config_set_no_image_expire, NULL, RSRC_CONF,
                  "Default expire time for Cache-Control/Expires/Edge-Control headers for NOIMAGE image, in seconds."
                  "The default is 60"),
    AP_INIT_TAKE1("DimsMaxSourceBytes",
                  dims_config_set_max_source_bytes, NULL, RSRC_CONF,
                  "Largest source image to accept, in bytes. A source larger than "
                  "this is refused before it is decoded. The default is 0, which "
                  "means no limit."),
    AP_INIT_FLAG("DimsAllowPrivateAddresses",
                  dims_config_set_allow_private_addresses, NULL, RSRC_CONF,
                  "Whether a fetch may reach a private address, meaning "
                  "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and IPv6 unique "
                  "local. The default is On. Loopback, link local, multicast, "
                  "and the reserved ranges are refused whatever this is set to."),
    AP_INIT_TAKE1("DimsAllowlistSigned",
                  dims_config_set_allowlist_signed, NULL, RSRC_CONF,
                  "Whether the host allowlist applies to a signed request and "
                  "to a redirect. Set log to record what enforcing would "
                  "refuse, or enforce to refuse it. The default is log."),
    AP_INIT_TAKE1("DimsAnimatedImages",
                  dims_config_set_animated_images, NULL, RSRC_CONF,
                  "How a source with more than one frame is handled. Set "
                  "passthrough to return it unchanged, or transform to run the "
                  "commands over every frame. Every frame costs memory and "
                  "time, so transform is the slower and larger answer. The "
                  "default is passthrough."),
    AP_INIT_TAKE1("DimsOverlayCacheMaxEntries",
                  dims_config_set_overlay_cache_max_entries, NULL, RSRC_CONF,
                  "Largest number of overlay images to keep on disk. The oldest "
                  "go first. The default is 1024, and 0 means no limit."),
    AP_INIT_TAKE1("DimsOverlayCacheMaxAge",
                  dims_config_set_overlay_cache_max_age, NULL, RSRC_CONF,
                  "How long an overlay image stays on disk, in seconds. The "
                  "default is 86400, and 0 means it never expires."),
    AP_INIT_TAKE1("DimsOriginStatusMode",
                  dims_config_set_origin_status_mode, NULL, RSRC_CONF,
                  "How a failure at the origin reaches the caller. Set forward "
                  "to report the status the origin returned, or map to report "
                  "404 for a missing source, 504 for a timeout, and 502 for "
                  "every other origin failure. The default is forward."),
    AP_INIT_FLAG("DimsStatusVerbose",
                  dims_config_set_status_verbose, NULL, RSRC_CONF,
                  "Whether the status handler prints the mod_dims, ImageMagick, "
                  "and libcurl versions. The default is On."),
    AP_INIT_TAKE1("DimsDownloadTimeout",
                  dims_config_set_download_timeout, NULL, RSRC_CONF,
                  "Timeout for downloading remote images."
                  "The default is 3000."),
    AP_INIT_TAKE1("DimsImagemagickTimeout",
                  dims_config_set_imagemagick_timeout, NULL, RSRC_CONF,
                  "Timeout for processing images."
                  "The default is 3000."),
    AP_INIT_TAKE1("DimsImagemagickMemorySize",
                  dims_config_set_imagemagick_memory_size, NULL, RSRC_CONF,
                  "Maximum amount of memory in megabytes to use for pixel cache."
                  "The default is 512mb."),
    AP_INIT_TAKE1("DimsImagemagickAreaSize",
                  dims_config_set_imagemagick_area_size, NULL, RSRC_CONF,
                  "Maximum amount of memory in megabytes that any one image can use."
                  "The default is 128mb."),
    AP_INIT_TAKE1("DimsImagemagickMapSize",
                  dims_config_set_imagemagick_map_size, NULL, RSRC_CONF,
                  "Maximum amount of memory map in megabytes to use for the pixel cache."
                  "The default is 1024mb."),
    AP_INIT_TAKE1("DimsImagemagickDiskSize",
                  dims_config_set_imagemagick_disk_size, NULL, RSRC_CONF,
                  "Maximum amount of disk space in megabytes to use for the pixel cache."
                  "The default is 1024mb."),
    AP_INIT_TAKE1("DimsSecretMaxExpiryPeriod",
                dims_config_set_secretkeyExpiryPeriod, NULL, RSRC_CONF,
                "How long in the future (in seconds) can the expiry date on the URL be requesting. 0 = forever"
                "The default is 0."),
    AP_INIT_TAKE1("DimsStripMetadata",
                dims_config_set_strip_metadata, NULL, RSRC_CONF,
                "Should DIMS strip the metadata from the image, true OR false."
                "The default is true."),
    AP_INIT_TAKE1("DimsIncludeDisposition",
                dims_config_set_include_disposition, NULL, RSRC_CONF,
                "Should DIMS include Content-Disposition header, true OR false."
                "The default is false."),
    AP_INIT_TAKE1("DimsOptimizeResize",
                dims_config_set_optimize_resize, NULL, RSRC_CONF,
                "Should DIMS optimize resize operations. This has a slight impact on image quality. 0 = disabled"
                "The default is 0."),
    AP_INIT_TAKE1("DimsDisableEncodedFetch",
                dims_config_set_encoded_fetch, NULL, RSRC_CONF,
                "Should DIMS encode image url before fetching it."
                "The default is 0."),
    AP_INIT_TAKE1("DimsEncryptionAlgorithm",
                dims_config_set_encryption_algorithm, NULL, RSRC_CONF,
                "What algorithm should DIMS user to decrypt the 'eurl' parameter."
                "The default is AES/ECB/PKCS5Padding."),
    AP_INIT_TAKE1("DimsDefaultOutputFormat",
                dims_config_set_default_output_format, NULL, RSRC_CONF,
                "Default output format if 'format' command is not present in the request."),
    AP_INIT_TAKE1("DimsUserAgentEnabled",
                dims_config_set_user_agent_enabled, NULL, RSRC_CONF,
                "Enable DIMS User-Agent header ('dims/<version>'), true OR false."
                "The default is false."),
    AP_INIT_TAKE1("DimsUserAgentOverride",
                dims_config_set_user_agent_override, NULL, RSRC_CONF,
                "Override DIMS User-Agent header"
                "The default is 'dims/<version>."),
    {NULL}
};
