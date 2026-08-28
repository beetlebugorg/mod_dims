/*
 * The server configuration and the directives that fill it.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_CONFIGURATION_H
#define _DIMS_CONFIGURATION_H

#include "mod_dims.h"

/*
 * The ImageMagick resource defaults, in megabytes. One place, so the value the
 * code sets and the value the help text prints cannot drift.
 */
#define DIMS_AREA_SIZE_MB 128
#define DIMS_MEMORY_SIZE_MB 512
#define DIMS_MAP_SIZE_MB 1024
#define DIMS_DISK_SIZE_MB 2048

#define DIMS_STRINGIFY_(x) #x
#define DIMS_MB_TEXT(x) DIMS_STRINGIFY_(x) "mb"
#include "module.h"

/* Builds a dims_config_rec with the documented defaults. httpd calls this
 * once per server through the module record. */
void *dims_create_config(apr_pool_t *p, server_rec *s);

/* Every directive mod_dims accepts. */
extern const command_rec dims_directives[];

#endif
