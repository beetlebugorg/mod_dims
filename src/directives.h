
#ifndef _DIRECTIVES_H_
#define _DIRECTIVES_H_

#include <httpd.h>
#include <http_config.h>

#include "configuration.h"

static const command_rec dims_directives[] = 
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
    AP_INIT_TAKE1("DimsEncryptionAlgorithm",
                dims_config_set_encryption_algorithm, NULL, RSRC_CONF,
                "What algorithm should DIMS user to decrypt the 'eurl' parameter."
                "The default is AES/ECB/PKCS5Padding."),
    AP_INIT_TAKE1("DimsDefaultOutputFormat",
                dims_config_set_default_output_format, NULL, RSRC_CONF,
                "Default output format if 'format' command is not present in the request."),
    AP_INIT_TAKE1("DimsUserAgentOverride",
                dims_config_set_user_agent_override, NULL, RSRC_CONF,
                "Override DIMS User-Agent header"
                "The default is 'dims/<version>."),
    {NULL}
};

#endif