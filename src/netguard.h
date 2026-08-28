/*
 * The network guard.
 *
 * Every fetch passes through this file before a socket opens. It answers three
 * questions: is the scheme one this service speaks, is the address one a real
 * image origin can hold, and is the host one the operator named.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_NETGUARD_H
#define _DIMS_NETGUARD_H

#include "mod_dims.h"

/*
 * How many redirects one fetch may follow. go-dims uses the same number.
 */
#define DIMS_MAX_REDIRECTS 3

/*
 * What the allowlist does on one fetch.
 *
 * SKIP is the error image, which the operator configured and the caller
 * cannot name. LOG and ENFORCE are the two values of DimsAllowlistSigned.
 */
typedef enum {
    DIMS_ALLOWLIST_SKIP = 0,
    DIMS_ALLOWLIST_LOG,
    DIMS_ALLOWLIST_ENFORCE
} dims_allowlist_mode;

/* Why the guard refused. DIMS_NET_OK is zero, so a check reads as a boolean. */
typedef enum {
    DIMS_NET_OK = 0,
    DIMS_NET_BAD_SCHEME,
    DIMS_NET_BAD_URL,
    DIMS_NET_RESERVED_ADDRESS,
    DIMS_NET_PRIVATE_ADDRESS,
    DIMS_NET_HOST_NOT_ALLOWED,
    DIMS_NET_TOO_MANY_REDIRECTS
} dims_net_result;

/* A sentence for the log. The caller never sends this to the client. */
const char *dims_net_reason(dims_net_result result);

/*
 * Whether an address may be connected to.
 *
 * allow_private turns off the second tier only. Loopback, link local,
 * multicast, unspecified, and the ranges reserved for documentation and
 * benchmarking are refused whatever it is set to, because no image origin
 * holds one.
 *
 * An IPv4 address mapped into IPv6 is judged as IPv4, so ::ffff:169.254.169.254
 * is refused along with 169.254.169.254.
 */
dims_net_result dims_address_allowed(const struct sockaddr *addr, socklen_t len,
                                     int allow_private);

/*
 * Whether a host matches the allowlist.
 *
 * The match walks the name from the left, dropping one label at a time. An
 * exact entry matches the whole name. An entry recorded as a glob matches a
 * name below it. An empty allowlist matches nothing.
 */
int dims_host_allowed(apr_table_t *whitelist, const char *hostname);

/*
 * Checks a URL before any connection.
 *
 * In DIMS_ALLOWLIST_LOG mode a host outside the allowlist is recorded and
 * allowed, so an operator can fill the allowlist from the log before moving to
 * DIMS_ALLOWLIST_ENFORCE.
 */
dims_net_result dims_validate_image_url(dims_request_rec *d, const char *url,
                                        dims_allowlist_mode mode);

/*
 * Installs the guard on a curl handle.
 *
 * The mode carries to every redirect hop.
 */
void dims_netguard_install(CURL *handle, dims_request_rec *d,
                           dims_allowlist_mode mode);

/*
 * Reads a Location header during a fetch and records a refusal on the request.
 *
 * The address callback covers a redirect that resolves to a refused address.
 * This covers a redirect that resolves fine and is simply not a host the
 * operator named.
 */
void dims_netguard_check_redirect(dims_request_rec *d, const char *location);

/* Logs once at startup for each tier the operator left permissive. */
void dims_netguard_log_configuration(server_rec *s, dims_config_rec *config);

#endif
