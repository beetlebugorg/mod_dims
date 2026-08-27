/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DIMS_TEST_ENVIRONMENT_H
#define DIMS_TEST_ENVIRONMENT_H

/*
 * The golden directory name for this build. Golden bytes depend on the
 * ImageMagick build and on the architecture, so the name carries both.
 *
 *     debian12-im6.9.13_x86_64
 *
 * This mirrors getEnvironment() in
 * ../go-dims/internal/commands/golden_test.go.
 */
const char *dims_test_environment(void);

#endif
