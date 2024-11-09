
#include "mod_dims.h"
#include "module.h"

#include <apr_lib.h>
#include <apr_hash.h>

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
    config->disk_size = 2048ul * 1024ul * 1024ul;  // 2048mb max.

    config->curl_queue_size = 10;
    config->cache_dir = NULL;
    config->secret_key = apr_pstrdup(p,"m0d1ms");
    config->encryption_algorithm = "aes/ecb/pkcs5padding";
    config->max_expiry_period= 0; // never expire

    return (void *) config;
}

const char *
dims_config_set_whitelist(cmd_parms *cmd, void *d, int argc, char *const argv[])
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, 
            &dims_module);
    int i;

    for(i = 0; i < argc; i++) {
        char *hostname = argv[i];

        /* remove glob character and '.' if they're on the string and set
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

const char *
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

const char *
dims_config_set_default_expire(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->default_expire = atol(arg);
    return NULL;
}

const char *
dims_config_set_no_image_expire(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->no_image_expire = atol(arg);
    return NULL;
}

const char *
dims_config_set_download_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->download_timeout = atol(arg);
    return NULL;
}

const char *
dims_config_set_imagemagick_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->imagemagick_timeout = atol(arg);
    return NULL;
}

const char *
dims_config_set_strip_metadata(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    // the default is 1, so anything other than "false" will use the default
    if(strcmp(arg, "false") == 0) {
        config->strip_metadata = 0;
    }
    else {
        config->strip_metadata = 1;
    }
    return NULL;
}

const char *
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

const char *
dims_config_set_optimize_resize(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->optimize_resize = atof(arg);
    return NULL;
}

const char *
dims_config_set_encoded_fetch(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->disable_encoded_fetch = atoi(arg);
    return NULL;
}

const char *
dims_config_set_encryption_algorithm(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->encryption_algorithm = (char *) arg;
    return NULL;
}

const char *
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

const char *
dims_config_set_user_agent_override(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    char *user_agent = (char *) arg;
    config->user_agent_override = user_agent;
    return NULL;
}

const char *
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

const char *
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

        switch(argc) {
            case 8:
                if(strcmp(argv[7], "-") != 0) {
                    client_config->secret_key = argv[7];
                } else {
                    client_config->secret_key = NULL;
                }
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
            case 5:
                if(strcmp(argv[4], "trust") == 0) {
                    client_config->trust_src = 1;
                }
            case 4:
                if(strcmp(argv[3], "-") != 0) {
                    client_config->edge_control_downstream_ttl = atoi(argv[3]);
                }
            case 3:
                if(strcmp(argv[2], "-") != 0) {
                    client_config->cache_control_max_age = atoi(argv[2]);
                }
            case 2:
                if(strcmp(argv[1], "-") != 0) {
                    client_config->no_image_url = argv[1];
                }
            case 1:
                client_config->id = argv[0];
        }
    }

    apr_hash_set(config->clients, argv[0], APR_HASH_KEY_STRING, client_config);

    return NULL;
}

const char *
dims_config_set_no_image_url(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->no_image_url = (char *) arg;
    return NULL;
}

const char *
dims_config_set_image_prefix(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->default_image_prefix = (char *) arg;

    if (strncmp(config->default_image_prefix, "https://", 8) != 0 &&
        strncmp(config->default_image_prefix, "http://", 7) != 0) {
        return "dimsdefaultimageprefix must start with 'https://' or 'http://'";
    }

    return NULL;
}

const char *
dims_config_set_imagemagick_disk_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->disk_size = atol(arg) * 1024 * 1024;
    
    return NULL;
}

const char *
dims_config_set_secretkeyExpiryPeriod(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->max_expiry_period = atol(arg);
    return NULL;
}

const char *
dims_config_set_imagemagick_area_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->area_size = atol(arg) * 1024 * 1024;
    return NULL;
}

const char *
dims_config_set_imagemagick_map_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->map_size = atol(arg) * 1024 * 1024;
    return NULL;
}

const char *
dims_config_set_imagemagick_memory_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            cmd->server->module_config, &dims_module);
    config->memory_size = atol(arg) * 1024 * 1024;
    return NULL;
}
