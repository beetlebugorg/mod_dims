/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_STUB_HTTPD_H
#define DIMS_TEST_STUB_HTTPD_H

#include "mod_dims.h"
#include "netguard.h"

#include <ctype.h>

/* Where the stub downloader reads fixtures from. */
const char *dims_stub_fixture_dir(void);

/* Print what the module logs. Off by default: a passing run stays quiet. */
void dims_stub_log_enable(int enabled);

#endif
