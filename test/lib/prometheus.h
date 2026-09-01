/*
 * Reading a Prometheus exposition body in a case.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_PROMETHEUS_H
#define DIMS_TEST_PROMETHEUS_H

#include "request.h"

/* Whether the body holds the text. The body needs no terminator. */
int dims_prom_contains(const dims_response *response, const char *text);

/*
 * The value of the sample whose line starts with prefix, which is a metric
 * name and its label set:
 *
 *     dims_requests_total{endpoint="dims4",outcome="success"}
 *
 * Returns -1 when no line starts with it.
 */
double dims_prom_value(const dims_response *response, const char *prefix);

#endif
