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

#ifndef _MOD_DIMS_H
#define _MOD_DIMS_H

#define MODULE_RELEASE "$Revision: $"
#define MODULE_VERSION "4.0.0alpha"

#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_file_info.h>
#include <apr_atomic.h>
#include <apr_queue.h>
#include <apr_base64.h>
#include <apr_escape.h>
#include <apr_lib.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_request.h>
#include <http_log.h>
#include <http_protocol.h>

#include <MagickWand/MagickWand.h>

#include <curl/curl.h>

#include "request.h"

#define DIMS_IGNORE -1
#define DIMS_SUCCESS 200 
#define DIMS_FAILURE 500 
#define DIMS_FILE_NOT_FOUND 404
#define DIMS_DOWNLOAD_TIMEOUT 1000
#define DIMS_IMAGEMAGICK_TIMEOUT 1001
#define DIMS_BAD_CLIENT 1002
#define DIMS_BAD_URL 1003 
#define DIMS_BAD_ARGUMENTS 1004
#define DIMS_HOSTNAME_NOT_IN_WHITELIST 1005
#define DIMS_INVALID_SIGNATURE 1006
#define DIMS_MISSING_SECRET 1007
#define DIMS_DECRYPTION_FAILURE 1008


apr_status_t dims_handle_dims3(dims_request_rec *d);
apr_status_t dims_handle_dims4(dims_request_rec *d);

typedef struct {
    apr_uint32_t success_count;
    apr_uint32_t failure_count;
    apr_uint32_t download_timeout_count;
    apr_uint32_t imagemagick_timeout_count;
} dims_stats_rec;

extern dims_stats_rec *stats;

#endif
