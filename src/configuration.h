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
#include "module.h"

/* Builds a dims_config_rec with the documented defaults. httpd calls this
 * once per server through the module record. */
void *dims_create_config(apr_pool_t *p, server_rec *s);

/* Every directive mod_dims accepts. */
extern const command_rec dims_directives[];

#endif
