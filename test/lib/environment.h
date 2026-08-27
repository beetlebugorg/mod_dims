/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_ENVIRONMENT_H
#define DIMS_TEST_ENVIRONMENT_H

/*
 * The golden directory name for this build.
 *
 * Golden bytes depend on the ImageMagick build, so the name carries the
 * distribution and the ImageMagick version. It does not carry the
 * architecture: amd64 and arm64 were measured to produce all 90 files byte
 * for byte identical.
 *
 * Keeping one set is deliberate. Two sets would let the architectures drift
 * apart without anything noticing, because each would only ever be compared
 * against itself. With one set, the arm64 job proves on every pull request
 * that the output does not depend on the architecture, and says so loudly the
 * day that stops being true.
 */
const char *dims_test_environment(void);

#endif
