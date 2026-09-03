/*
 * The network guard.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "netguard.h"
#include "metrics.h"

#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* One CIDR block, held in host byte order so a compare is a mask and a test. */
typedef struct {
    apr_uint32_t network;
    int prefix;
    const char *name;
} dims_v4_block;

/* Ranges no image origin holds. Refused whatever DimsAllowPrivateAddresses
 * says. */
static const dims_v4_block dims_v4_reserved[] = {
    { 0x00000000U,  8, "this network" },
    { 0x64400000U, 10, "carrier grade NAT" },
    { 0x7F000000U,  8, "loopback" },
    { 0xA9FE0000U, 16, "link local" },
    { 0xC0000000U, 24, "IETF protocol assignments" },
    { 0xC0000200U, 24, "documentation" },
    { 0xC6120000U, 15, "benchmarking" },
    { 0xC6336400U, 24, "documentation" },
    { 0xCB007100U, 24, "documentation" },
    { 0xE0000000U,  4, "multicast" },
    { 0xF0000000U,  4, "reserved" },
    { 0, 0, NULL }
};

/* Ranges a private origin does hold. DimsAllowPrivateAddresses covers these. */
static const dims_v4_block dims_v4_private[] = {
    { 0x0A000000U,  8, "private" },
    { 0xAC100000U, 12, "private" },
    { 0xC0A80000U, 16, "private" },
    { 0, 0, NULL }
};

const char *
dims_net_reason(dims_net_result result)
{
    switch (result) {
        case DIMS_NET_OK:                  return "allowed";
        case DIMS_NET_BAD_SCHEME:          return "the scheme is not http or https";
        case DIMS_NET_BAD_URL:             return "the URL does not parse";
        case DIMS_NET_RESERVED_ADDRESS:    return "the address is not a public address";
        case DIMS_NET_PRIVATE_ADDRESS:     return "the address is private and "
                                                  "DimsAllowPrivateAddresses is off";
        case DIMS_NET_HOST_NOT_ALLOWED:    return "the host is not on the allowlist";
        case DIMS_NET_TOO_MANY_REDIRECTS:  return "the redirect chain is too long";
        default:                           return "refused";
    }
}

static int
dims_v4_in_block(apr_uint32_t address, const dims_v4_block *block)
{
    /* A shift by 32 is undefined, so a /0 would have to be special cased. No
     * block below uses one. */
    apr_uint32_t mask = 0xFFFFFFFFU << (32 - block->prefix);

    return (address & mask) == block->network;
}

static dims_net_result
dims_v4_allowed(apr_uint32_t address, int allow_private)
{
    const dims_v4_block *block;

    for (block = dims_v4_reserved; block->name != NULL; block++) {
        if (dims_v4_in_block(address, block)) {
            return DIMS_NET_RESERVED_ADDRESS;
        }
    }

    if (allow_private) {
        return DIMS_NET_OK;
    }

    for (block = dims_v4_private; block->name != NULL; block++) {
        if (dims_v4_in_block(address, block)) {
            return DIMS_NET_PRIVATE_ADDRESS;
        }
    }

    return DIMS_NET_OK;
}

static dims_net_result
dims_v6_allowed(const struct in6_addr *address, int allow_private)
{
    const unsigned char *b = address->s6_addr;
    int i;

    /* An IPv4 address wearing an IPv6 shape. Judge it as what it is, or
     * ::ffff:169.254.169.254 walks past every rule above. */
    if (IN6_IS_ADDR_V4MAPPED(address)) {
        apr_uint32_t mapped;

        memcpy(&mapped, b + 12, sizeof(mapped));

        return dims_v4_allowed(ntohl(mapped), allow_private);
    }

    /* :: and ::1 */
    for (i = 0; i < 15; i++) {
        if (b[i] != 0) {
            break;
        }
    }
    if (i == 15 && (b[15] == 0 || b[15] == 1)) {
        return DIMS_NET_RESERVED_ADDRESS;
    }

    /* ff00::/8 multicast */
    if (b[0] == 0xFF) {
        return DIMS_NET_RESERVED_ADDRESS;
    }

    /* fe80::/10 link local */
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) {
        return DIMS_NET_RESERVED_ADDRESS;
    }

    /* 64:ff9b::/96, the well known IPv4 translation prefix */
    if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B) {
        return DIMS_NET_RESERVED_ADDRESS;
    }

    /* 100::/64, the discard prefix */
    if (b[0] == 0x01 && b[1] == 0x00) {
        for (i = 2; i < 8; i++) {
            if (b[i] != 0) {
                break;
            }
        }
        if (i == 8) {
            return DIMS_NET_RESERVED_ADDRESS;
        }
    }

    /* 2001:db8::/32, documentation */
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) {
        return DIMS_NET_RESERVED_ADDRESS;
    }

    if (allow_private) {
        return DIMS_NET_OK;
    }

    /* fc00::/7, unique local */
    if ((b[0] & 0xFE) == 0xFC) {
        return DIMS_NET_PRIVATE_ADDRESS;
    }

    return DIMS_NET_OK;
}

dims_net_result
dims_address_allowed(const struct sockaddr *addr, socklen_t len, int allow_private)
{
    if (addr == NULL) {
        return DIMS_NET_RESERVED_ADDRESS;
    }

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *) addr;

        if (len < (socklen_t) sizeof(*v4)) {
            return DIMS_NET_RESERVED_ADDRESS;
        }

        return dims_v4_allowed(ntohl(v4->sin_addr.s_addr), allow_private);
    }

    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *) addr;

        if (len < (socklen_t) sizeof(*v6)) {
            return DIMS_NET_RESERVED_ADDRESS;
        }

        return dims_v6_allowed(&v6->sin6_addr, allow_private);
    }

    /* A unix socket, or anything else libcurl offers. Not an image origin. */
    return DIMS_NET_RESERVED_ADDRESS;
}

int
dims_host_allowed(apr_table_t *whitelist, const char *hostname)
{
    /*
     * Walk the name from the left, dropping one label each time. The first
     * pass must match an entry recorded as "exact"; every pass after it must
     * match one recorded as "glob".
     */
    const char *state = "exact";
    int found = 0, done = 0;

    if (whitelist == NULL || hostname == NULL) {
        return 0;
    }

    while (!done) {
        const char *value = apr_table_get(whitelist, hostname);

        if (value && strcmp(value, state) == 0) {
            done = found = 1;
        } else {
            hostname = strchr(hostname, '.');
            if (!hostname) {
                done = 1;
            } else {
                hostname++;
            }
            state = "glob";
        }
    }

    return found;
}

static dims_net_result
validate_url(dims_request_rec *d, const char *url, dims_allowlist_mode mode)
{
    apr_uri_t uri;

    if (url == NULL || apr_uri_parse(d->pool, url, &uri) != APR_SUCCESS) {
        return DIMS_NET_BAD_URL;
    }

    if (uri.scheme == NULL ||
            (strcasecmp(uri.scheme, "http") != 0 &&
             strcasecmp(uri.scheme, "https") != 0)) {
        return DIMS_NET_BAD_SCHEME;
    }

    if (uri.hostname == NULL || *uri.hostname == '\0') {
        return DIMS_NET_BAD_URL;
    }

    if (mode != DIMS_ALLOWLIST_SKIP) {
        int allowed = dims_host_allowed(d->config->whitelist, uri.hostname);

        dims_metrics_allowlist(mode, allowed);

        if (!allowed) {
            if (mode == DIMS_ALLOWLIST_ENFORCE) {
                return DIMS_NET_HOST_NOT_ALLOWED;
            }

            /* Report what enforcing would cost, so an operator can fill the
             * allowlist from the log before setting the directive. */
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, d->r,
                          "DimsAllowlistSigned enforce would refuse %s: %s, "
                          "on request: %s", uri.hostname,
                          dims_net_reason(DIMS_NET_HOST_NOT_ALLOWED),
                          d->r->uri);
        }
    }

    return DIMS_NET_OK;
}

/* Records the result, so every refusal counts once whatever refused it. */
dims_net_result
dims_validate_image_url(dims_request_rec *d, const char *url,
                        dims_allowlist_mode mode)
{
    dims_net_result result = validate_url(d, url, mode);

    dims_metrics_netguard(result);

    return result;
}

/*
 * Runs once per connection, after the name resolves and before the socket
 * opens. A name that resolves to a refused address is refused whatever it is
 * called, and every redirect hop arrives here on its own.
 */
static curl_socket_t
dims_opensocket_cb(void *clientp, curlsocktype purpose, struct curl_sockaddr *address)
{
    dims_request_rec *d = (dims_request_rec *) clientp;
    dims_net_result result;
    char text[INET6_ADDRSTRLEN] = "";

    if (purpose != CURLSOCKTYPE_IPCXN) {
        return CURL_SOCKET_BAD;
    }

    result = dims_address_allowed(&address->addr, (socklen_t) address->addrlen,
                                  d->config->allow_private_addresses);
    if (result == DIMS_NET_OK) {
        return socket(address->family, address->socktype, address->protocol);
    }

    if (address->family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *) &address->addr;
        inet_ntop(AF_INET, &v4->sin_addr, text, sizeof(text));
    } else if (address->family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *) &address->addr;
        inet_ntop(AF_INET6, &v6->sin6_addr, text, sizeof(text));
    }

    d->net_refusal = result;

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                  "Refused a connection to %s: %s, on request: %s",
                  text, dims_net_reason(result), d->r->uri);

    return CURL_SOCKET_BAD;
}

void
dims_netguard_install(CURL *handle, dims_request_rec *d, dims_allowlist_mode mode)
{
    d->net_apply_allowlist = (int) mode;

    /* Clear what a previous fetch on this request refused, so the error image
     * fetch behind it is not stopped by a stale refusal. */
    d->net_refusal = DIMS_NET_OK;

    curl_easy_setopt(handle, CURLOPT_OPENSOCKETFUNCTION, dims_opensocket_cb);
    curl_easy_setopt(handle, CURLOPT_OPENSOCKETDATA, d);

    /* A scheme libcurl handles without a socket never reaches the address
     * callback, so name the two protocols on the handle. */
#if LIBCURL_VERSION_NUM >= 0x075500 /* 7.85.0 */
    curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(handle, CURLOPT_PROTOCOLS,
                     (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
    curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS,
                     (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif

    curl_easy_setopt(handle, CURLOPT_MAXREDIRS, (long) DIMS_MAX_REDIRECTS);
}

void
dims_netguard_check_redirect(dims_request_rec *d, const char *location)
{
    dims_allowlist_mode mode = (dims_allowlist_mode) d->net_apply_allowlist;
    apr_uri_t uri;
    dims_net_result result;

    if (location == NULL) {
        return;
    }

    /* The header parser hands over the value with the space after the colon
     * still on the front, and apr_uri_parse refuses a URL that starts with
     * one. */
    while (*location == ' ' || *location == '\t') {
        location++;
    }

    if (*location == '\0') {
        return;
    }

    if (apr_uri_parse(d->pool, location, &uri) != APR_SUCCESS) {
        d->net_refusal = DIMS_NET_BAD_URL;
        return;
    }

    /* A relative target keeps the host of the hop it came from, which the
     * check on that hop already passed. */
    if (uri.hostname == NULL) {
        return;
    }

    result = DIMS_NET_OK;
    if (uri.scheme == NULL ||
            (strcasecmp(uri.scheme, "http") != 0 &&
             strcasecmp(uri.scheme, "https") != 0)) {
        /* The scheme check holds whatever the allowlist mode is. A redirect
         * into file:// or gopher:// is never a legitimate image. */
        result = DIMS_NET_BAD_SCHEME;
    } else if (mode != DIMS_ALLOWLIST_SKIP &&
            !dims_host_allowed(d->config->whitelist, uri.hostname)) {
        result = DIMS_NET_HOST_NOT_ALLOWED;
    }

    if (result == DIMS_NET_HOST_NOT_ALLOWED && mode == DIMS_ALLOWLIST_LOG) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, d->r,
                      "DimsAllowlistSigned enforce would refuse a redirect to "
                      "%s, on request: %s", uri.hostname, d->r->uri);
        return;
    }

    if (result != DIMS_NET_OK) {
        d->net_refusal = result;

        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, d->r,
                      "Refused a redirect to %s: %s, on request: %s",
                      uri.hostname, dims_net_reason(result), d->r->uri);
    }
}

void
dims_netguard_log_configuration(server_rec *s, dims_config_rec *config)
{
    const char *name = (s->server_hostname != NULL) ? s->server_hostname : "";

    /* A warning, because the default httpd LogLevel is warn and anything
     * quieter is invisible. */
    if (config->allow_private_addresses) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "mod_dims will connect to private addresses on %s. "
                     "Set DimsAllowPrivateAddresses off to refuse them.", name);
    }

    if (!config->allowlist_signed) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "mod_dims does not apply the allowlist to a signed request "
                     "or to a redirect on %s. Set DimsAllowlistSigned enforce "
                     "to apply it.", name);
    }
}
