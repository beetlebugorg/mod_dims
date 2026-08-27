/*
 * Fetching a source image.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _DIMS_CURL_H
#define _DIMS_CURL_H

#include "mod_dims.h"

/* Where the shared handle hangs off the process pool. */
#define DIMS_CURL_SHARED_KEY "dims_curl_shared"

/*
 * The shared curl handle and the locks it needs.
 *
 * Sharing lets one process reuse the DNS cache across requests instead of
 * resolving again on every one.
 */
typedef struct {
    CURLSH *share;

    server_rec *s;

    apr_thread_mutex_t *share_mutex;
    apr_thread_mutex_t *dns_mutex;
} dims_curl_rec;

/*
 * Downloads fetch_url into data.
 *
 * data->data comes from malloc, not from a pool, so the caller frees it.
 */
CURLcode dims_get_image_data(dims_request_rec *d, char *fetch_url,
                             dims_image_data_t *data);

/* Locking for the shared handle. curl calls these. */
void lock_share(CURL *handle, curl_lock_data data, curl_lock_access access,
                void *userptr);
void unlock_share(CURL *handle, curl_lock_data data, void *userptr);

#endif
