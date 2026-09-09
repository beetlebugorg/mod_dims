/*
 * What the dims-sign command needs and no client does.
 *
 * This header is not installed. A /dims4/ message contains the client secret,
 * so the installed header does not offer it.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_SIGN_INTERNAL_H
#define DIMS_SIGN_INTERNAL_H

#include "dims_sign.h"

/*
 * Builds the message dims_sign_dims4_url hashes.
 *
 * The message is the expiry, the secret, the commands, the image URL, and the
 * value of each name _keys lists, joined with nothing between them.
 *
 * On DIMS_SIGN_OK, *out holds the message. Release it with dims_sign_free.
 */
dims_sign_status dims_sign_dims4_message(const char *url, const char *secret,
                                         const char *prefix, char **out);

#endif
