/*
 * The module record httpd registers.
 *
 * Every file that reads the server configuration needs this, because
 * ap_get_module_config is keyed on it.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_MODULE_H
#define _DIMS_MODULE_H

#include <httpd.h>
#include <http_config.h>

extern module AP_MODULE_DECLARE_DATA dims_module;

#endif
