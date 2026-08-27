/*
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "environment.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Reads one key from /etc/os-release into buf. Returns 0 on success. */
static int
read_os_release(const char *key, char *buf, size_t len)
{
    FILE *f = fopen("/etc/os-release", "r");
    char line[256];
    size_t key_len = strlen(key);
    int found = 1;

    if (f == NULL) {
        return 1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        char *value;
        size_t value_len;

        if (strncmp(line, key, key_len) != 0 || line[key_len] != '=') {
            continue;
        }

        value = line + key_len + 1;
        value_len = strcspn(value, "\r\n");
        value[value_len] = '\0';

        /* Strip the quotes os-release puts around some values. */
        if (value[0] == '"') {
            value++;
            value_len = strcspn(value, "\"");
            value[value_len] = '\0';
        }

        snprintf(buf, len, "%s", value);
        found = 0;
        break;
    }

    fclose(f);
    return found;
}

const char *
dims_test_environment(void)
{
    static char environment[256];
    char distro[64] = "unknown";
    char version[32] = "0";
    char magick[64] = "unknown";
    const char *from_env;

    if (environment[0] != '\0') {
        return environment;
    }

    from_env = getenv("DIMS_TEST_ENV");
    if (from_env != NULL && from_env[0] != '\0') {
        snprintf(environment, sizeof(environment), "%s", from_env);
        return environment;
    }

    read_os_release("ID", distro, sizeof(distro));
    read_os_release("VERSION_ID", version, sizeof(version));

    /* The runtime image has no ImageMagick tooling, so the build records the
     * version it compiled against, already reduced to major.minor. */
    from_env = getenv("DIMS_TEST_IMAGEMAGICK_VERSION");
    if (from_env == NULL || from_env[0] == '\0') {
        static char recorded[64];
        FILE *version_file = fopen("/etc/dims-magick-version", "r");

        if (version_file != NULL) {
            if (fgets(recorded, sizeof(recorded), version_file) != NULL) {
                recorded[strcspn(recorded, "\r\n")] = '\0';
                from_env = recorded;
            }
            fclose(version_file);
        }
    }
    if (from_env != NULL && from_env[0] != '\0') {
        snprintf(magick, sizeof(magick), "%s", from_env);
    }

    snprintf(environment, sizeof(environment), "%s%s-im%s", distro, version, magick);

    return environment;
}
