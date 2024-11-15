
#ifndef _CONFIGURATION_H_
#define _CONFIGURATION_H_

#include <httpd.h>
#include <http_config.h>
#include <apr_hash.h>

typedef struct dims_config_rec dims_config_rec;
typedef struct dims_client_config_rec dims_client_config_rec;

void *dims_create_config(apr_pool_t *p, server_rec *s);
const char *dims_config_set_whitelist(cmd_parms *cmd, void *d, int argc, char *const argv[]);
const char *dims_config_set_ignore_default_output_format(cmd_parms *cmd, void *d, int argc, char *const argv[]);
const char *dims_config_set_default_expire(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_download_timeout(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_imagemagick_timeout(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_strip_metadata(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_include_disposition(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_encryption_algorithm(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_default_output_format(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_user_agent_override(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_client(cmd_parms *cmd, void *d, int argc, char *const argv[]);
const char *dims_config_set_error_image_background(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_error_image_expire(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_image_prefix(cmd_parms *cmd, void *dummy, const char *arg);
const char *dims_config_set_secretkey_expiry_period(cmd_parms *cmd, void *dummy, const char *arg);

struct dims_config_rec {
    int download_timeout;
    int imagemagick_timeout;

    apr_table_t *whitelist;
    apr_hash_t *clients;
    apr_table_t *ignore_default_output_format;

    char *error_image_background;
    long error_image_expire;
    long default_expire;
    int strip_metadata;
    int include_disposition;
    char *default_output_format;
    int curl_queue_size;
    char *secret_key;
    char *encryption_algorithm;
    long max_expiry_period;
    char *cache_dir;
    char *default_image_prefix;
    char *user_agent_override;
};

struct dims_client_config_rec {
    char *id;
    char *error_image_background;
    int cache_control_max_age;
    int edge_control_downstream_ttl;
    int trust_src;
    int min_src_cache_control;
    int max_src_cache_control;
    char *secret_key;
};

#endif