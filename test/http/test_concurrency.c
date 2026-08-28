/*
 * DimsMaxInFlight.
 *
 * The cap defaults to no cap, so the main test server cannot exercise it. The
 * server on port 8008 caps the image stage at one request.
 *
 * The origin serves /slow.png after a five second sleep, so a request there
 * holds its slot long enough for a second request to meet the cap.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../lib/common.h"

#include <pthread.h>
#include <unistd.h>

static const char *
capped_url(void)
{
    const char *from_env = getenv("DIMS_TEST_INFLIGHT_URL");
    return (from_env != NULL && from_env[0] != '\0') ? from_env
                                                     : "http://dims:8008";
}

/* Requests a fixture over /dims4/ against the capped server. Caller frees. */
static dims_response *
capped_request(const char *fixture)
{
    char *url = dims_fixture_url(fixture);
    char *path = dims_sign_dims4("resize/100x100", url, NULL, NULL);
    char full[2048];
    dims_response *response;

    snprintf(full, sizeof(full), "%s%s", capped_url(), path);
    response = dims_get_absolute(full);

    free(path);
    free(url);
    return response;
}

/* Thread body. Holds the only slot by requesting the slow origin. */
static void *
hold_the_slot(void *arg)
{
    dims_response *response = capped_request("slow.png");

    dims_response_free(response);
    (void) arg;
    return NULL;
}

/*
 * A slow request holds the only slot. A second request meets the cap and is
 * refused with 503. After the first finishes, the slot is free and an ordinary
 * request is served again.
 */
static void
test_over_the_cap_is_refused(void)
{
    pthread_t holder;
    dims_response *refused;
    dims_response *served;

    if (pthread_create(&holder, NULL, hold_the_slot, NULL) != 0) {
        FAIL("could not start the holder thread");
        return;
    }

    /* Let the holder take the slot before the second request arrives. */
    sleep(1);

    refused = capped_request("grid.png");
    CHECK(refused->transport_error == NULL, "the worker must answer: %s",
          refused->transport_error ? refused->transport_error : "");
    dims_test_logf("a second request while the slot is held returns %ld",
                   refused->status);
    CHECK_INT(refused->status, 503, "a request over the cap");
    dims_response_free(refused);

    pthread_join(holder, NULL);

    served = capped_request("grid.png");
    CHECK_INT(served->status, 200, "a request after the slot is free");
    dims_response_free(served);
}

const dims_test dims_tests_concurrency[] = {
    { "TestOverTheCapIsRefused", test_over_the_cap_is_refused, NULL },
    DIMS_TEST_END
};
