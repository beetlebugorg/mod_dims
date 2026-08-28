/*
 * The network guard, ported from ../go-dims/internal/core/network_test.go.
 *
 * The three cases there are pure functions over an address, a host, and a URL,
 * so they port to this binary rather than to the HTTP suite. The fetch cases
 * that need a socket stay in http/test_allowlist.c.
 *
 * Copyright (c) 2025 Jeremy Collins (go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to mod_dims)
 * SPDX-License-Identifier: MIT
 */

#include "fixture.h"
#include "netguard.h"
#include "../lib/test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

/* Judges one textual address, in whichever family it parses as. */
static dims_net_result
judge(const char *text, int allow_private)
{
    struct sockaddr_in6 v6;
    struct sockaddr_in v4;

    memset(&v6, 0, sizeof(v6));
    memset(&v4, 0, sizeof(v4));

    if (inet_pton(AF_INET, text, &v4.sin_addr) == 1) {
        v4.sin_family = AF_INET;
        return dims_address_allowed((struct sockaddr *) &v4, sizeof(v4),
                                    allow_private);
    }

    if (inet_pton(AF_INET6, text, &v6.sin6_addr) == 1) {
        v6.sin6_family = AF_INET6;
        return dims_address_allowed((struct sockaddr *) &v6, sizeof(v6),
                                    allow_private);
    }

    CHECK(0, "%s does not parse as an address", text);
    return DIMS_NET_OK;
}

/*
 * Ported: TestIsPublicAddress. Split in two, because mod_dims refuses these in
 * two tiers where go-dims refuses them in one. This is the tier that holds
 * whatever DimsAllowPrivateAddresses says.
 */
static void
test_is_public_address(void)
{
    static const char *refused[] = {
        "169.254.169.254",        /* EC2 and ECS instance metadata */
        "::ffff:169.254.169.254", /* the same address mapped into IPv6 */
        "127.0.0.1",
        "127.1.2.3",
        "::1",
        "0.0.0.0",
        "::",
        "100.64.0.1", /* carrier grade NAT */
        "198.18.0.1", /* benchmarking */
        "192.0.2.1",  /* documentation */
        "203.0.113.1",
        "224.0.0.1", /* multicast */
        "240.0.0.1", /* reserved */
        "255.255.255.255",
        "fe80::1", /* IPv6 link local */
        "ff02::1", /* IPv6 multicast */
        "2001:db8::1",
        NULL
    };
    static const char *allowed[] = {
        "8.8.8.8", "1.1.1.1", "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
        NULL
    };
    int i;

    for (i = 0; refused[i] != NULL; i++) {
        CHECK(judge(refused[i], 1) != DIMS_NET_OK, "%s must be refused",
              refused[i]);
    }

    for (i = 0; allowed[i] != NULL; i++) {
        CHECK_INT(judge(allowed[i], 1), DIMS_NET_OK, allowed[i]);
    }

    CHECK(dims_address_allowed(NULL, 0, 1) != DIMS_NET_OK,
          "no address must be refused");
}

/*
 * The second tier. These are refused only when the operator turns
 * DimsAllowPrivateAddresses off, because an origin inside the same network
 * really does hold one.
 */
static void
test_private_addresses_follow_the_directive(void)
{
    static const char *private_addresses[] = {
        "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "fd00::1",
        NULL
    };
    int i;

    for (i = 0; private_addresses[i] != NULL; i++) {
        CHECK_INT(judge(private_addresses[i], 1), DIMS_NET_OK,
                  private_addresses[i]);
        CHECK_INT(judge(private_addresses[i], 0), DIMS_NET_PRIVATE_ADDRESS,
                  private_addresses[i]);
    }

    /* 172.15 and 172.32 sit outside the block. A mask that is one bit wide in
     * the wrong direction would take them too. */
    CHECK_INT(judge("172.15.0.1", 0), DIMS_NET_OK, "172.15.0.1");
    CHECK_INT(judge("172.32.0.1", 0), DIMS_NET_OK, "172.32.0.1");
}

/*
 * Ported: TestHostAllowed. The allowlist syntax differs. go-dims writes a
 * leading dot for a subdomain match, and mod_dims writes a leading star, so
 * the entries change and the property does not.
 */
static void
test_host_allowed(void)
{
    dims_request_rec *d = dims_fixture_request("grid.png", NULL);
    apr_table_t *list = d->config->whitelist;

    apr_table_setn(list, "images.example.com", "exact");
    apr_table_setn(list, "cdn.example.net", "glob");

    CHECK(dims_host_allowed(list, "images.example.com"), "the exact entry");
    CHECK(dims_host_allowed(list, "IMAGES.EXAMPLE.COM"), "matching ignores case");
    CHECK(dims_host_allowed(list, "a.cdn.example.net"), "a glob entry takes a subdomain");
    CHECK(dims_host_allowed(list, "a.b.cdn.example.net"), "and a deeper one");

    CHECK(!dims_host_allowed(list, "evil.example.com"), "another host under the domain");
    CHECK(!dims_host_allowed(list, "images.example.com.evil.test"),
          "a suffix must not match an exact entry");
    CHECK(!dims_host_allowed(list, "notcdn.example.net"), "a longer label");
    CHECK(!dims_host_allowed(list, "cdn.example.net"),
          "a glob entry does not match the domain itself");

    /*
     * An empty allowlist matches nothing. go-dims allows every host on an
     * empty list. mod_dims has always refused, and the two cannot agree here
     * without changing which URLs /dims3/ accepts.
     */
    CHECK(!dims_host_allowed(apr_table_make(d->pool, 1), "anything.example"),
          "an empty allowlist matches nothing");
    CHECK(!dims_host_allowed(NULL, "anything.example"), "no allowlist");

    dims_fixture_free(d);
}

/* Ported: TestValidateImageURL. */
static void
test_validate_image_url(void)
{
    static const char *refused[] = {
        "file:///etc/passwd", "gopher://x/1", "ftp://example.com/a.jpg",
        "dict://example.com/", "/relative/path.jpg",
        NULL
    };
    dims_request_rec *d = dims_fixture_request("grid.png", NULL);
    int i;

    for (i = 0; refused[i] != NULL; i++) {
        CHECK(dims_validate_image_url(d, refused[i], DIMS_ALLOWLIST_SKIP)
                  != DIMS_NET_OK,
              "%s must be refused", refused[i]);
    }

    CHECK_INT(dims_validate_image_url(d, "https://example.com/a.jpg",
                                      DIMS_ALLOWLIST_SKIP),
              DIMS_NET_OK, "an https source");
    CHECK_INT(dims_validate_image_url(d, "HTTP://example.com/a.jpg",
                                      DIMS_ALLOWLIST_SKIP),
              DIMS_NET_OK, "the scheme is not case sensitive");

    apr_table_setn(d->config->whitelist, "images.example.com", "exact");

    CHECK_INT(dims_validate_image_url(d, "https://example.com/a.jpg",
                                      DIMS_ALLOWLIST_ENFORCE),
              DIMS_NET_HOST_NOT_ALLOWED, "a host outside the allowlist");
    CHECK_INT(dims_validate_image_url(d, "https://example.com/a.jpg",
                                      DIMS_ALLOWLIST_LOG),
              DIMS_NET_OK, "log mode records the same host and allows it");
    CHECK_INT(dims_validate_image_url(d, "https://images.example.com/a.jpg",
                                      DIMS_ALLOWLIST_ENFORCE),
              DIMS_NET_OK, "a host on the allowlist");

    dims_fixture_free(d);
}

const dims_test dims_tests_unit_netguard[] = {
    { "TestIsPublicAddress", test_is_public_address, NULL },
    { "TestPrivateAddressesFollowTheDirective",
      test_private_addresses_follow_the_directive, NULL },
    { "TestHostAllowed", test_host_allowed, NULL },
    { "TestValidateImageURL", test_validate_image_url, NULL },
    DIMS_TEST_END
};
