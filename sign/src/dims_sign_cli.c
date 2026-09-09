/*
 * dims-sign, a command that signs and checks mod_dims URLs.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "dims_sign.h"
#include "dims_sign_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 0 a signature, 1 a mismatch, 2 a usage error, 3 a URL the command cannot
 * read. A script reads the number and not the text. */
#define EXIT_OK 0
#define EXIT_MISMATCH 1
#define EXIT_USAGE 2
#define EXIT_BAD_URL 3

typedef enum {
    ENDPOINT_NONE = 0,
    ENDPOINT_DIMS4,
    ENDPOINT_DIMS5
} endpoint;

typedef enum {
    MODE_SIGN = 0,
    MODE_MESSAGE,
    MODE_VERIFY,
    MODE_FIXTURE
} mode;

static void
usage(FILE *to)
{
    fputs(
        "usage: dims-sign (--dims4 | --dims5) [--key-file FILE] [--prefix P]\n"
        "                 [--message | --verify] URL\n"
        "       dims-sign --fixture < FILE\n"
        "\n"
        "  --dims4, --dims5  which endpoint signs the URL. The path does not\n"
        "                    say, so the caller names it.\n"
        "  --key-file FILE   read the key from FILE, or from standard input\n"
        "                    when FILE is -. Without this the key comes from\n"
        "                    DIMS_SIGNING_KEY.\n"
        "  --prefix P        what comes before the commands in the path.\n"
        "                    The default is /dims4/ or /dims5/.\n"
        "  --message         print the message the signer hashes. /dims5/\n"
        "                    only: a /dims4/ message holds the secret.\n"
        "  --verify          compare the signature the URL holds against the\n"
        "                    one the key produces.\n"
        "  --fixture         fill in the computed fields of the signing\n"
        "                    fixtures on standard input.\n",
        to);
}

/* -- Reading ------------------------------------------------------------ */

/* One line without its newline, or NULL at the end of the stream. */
static char *
read_line(FILE *from)
{
    size_t capacity = 128;
    size_t length = 0;
    char *line = malloc(capacity);
    int c;

    if (line == NULL) {
        return NULL;
    }

    c = fgetc(from);
    if (c == EOF) {
        free(line);
        return NULL;
    }

    while (c != EOF && c != '\n') {
        if (length + 1 >= capacity) {
            char *grown = realloc(line, capacity * 2);

            if (grown == NULL) {
                free(line);
                return NULL;
            }

            line = grown;
            capacity *= 2;
        }

        line[length++] = (char) c;
        c = fgetc(from);
    }

    line[length] = '\0';

    return line;
}

/* The key, with the trailing white space of a text file removed. */
static char *
read_key_file(const char *path)
{
    FILE *from = (strcmp(path, "-") == 0) ? stdin : fopen(path, "rb");
    size_t capacity = 256;
    size_t length = 0;
    char *key;
    size_t read;

    if (from == NULL) {
        fprintf(stderr, "dims-sign: cannot open %s\n", path);
        return NULL;
    }

    key = malloc(capacity);
    if (key == NULL) {
        return NULL;
    }

    while ((read = fread(key + length, 1, capacity - length - 1, from)) > 0) {
        char *grown;

        length += read;
        if (length + 1 < capacity) {
            break;
        }

        grown = realloc(key, capacity * 2);
        if (grown == NULL) {
            free(key);
            return NULL;
        }

        key = grown;
        capacity *= 2;
    }

    if (from != stdin) {
        fclose(from);
    }

    while (length > 0 && (key[length - 1] == '\n' || key[length - 1] == '\r' ||
                          key[length - 1] == ' ' || key[length - 1] == '\t')) {
        length--;
    }

    key[length] = '\0';

    return key;
}

/* -- The signature a URL already holds ---------------------------------- */

/* The last sig parameter of a /dims5/ URL, or NULL. */
static char *
dims5_signature(const char *url)
{
    const char *query = strchr(url, '?');
    const char *found = NULL;
    size_t length = 0;
    const char *at;
    char *copy;

    if (query == NULL) {
        return NULL;
    }

    at = query + 1;
    while (*at != '\0') {
        const char *end = strchr(at, '&');
        size_t token_length;

        if (end == NULL) {
            end = at + strlen(at);
        }

        token_length = (size_t) (end - at);
        if (token_length > 4 && memcmp(at, "sig=", 4) == 0) {
            found = at + 4;
            length = token_length - 4;
        }

        at = (*end == '\0') ? end : end + 1;
    }

    if (found == NULL) {
        return NULL;
    }

    copy = malloc(length + 1);
    if (copy != NULL) {
        memcpy(copy, found, length);
        copy[length] = '\0';
    }

    return copy;
}

/* The signature segment of a /dims4/ URL, which follows the client id. */
static char *
dims4_signature(const char *url, const char *prefix)
{
    const char *at = strstr(url, prefix);
    const char *end;
    char *copy;

    if (at == NULL) {
        return NULL;
    }

    at += strlen(prefix);
    at = strchr(at, '/');
    if (at == NULL) {
        return NULL;
    }

    at++;
    end = strchr(at, '/');
    if (end == NULL) {
        return NULL;
    }

    copy = malloc((size_t) (end - at) + 1);
    if (copy != NULL) {
        memcpy(copy, at, (size_t) (end - at));
        copy[end - at] = '\0';
    }

    return copy;
}

/* -- The modes ---------------------------------------------------------- */

static int
report(dims_sign_status status)
{
    fprintf(stderr, "dims-sign: %s\n", dims_sign_strerror(status));

    return (status == DIMS_SIGN_BAD_ARGUMENT) ? EXIT_USAGE : EXIT_BAD_URL;
}

static int
run_sign(endpoint which, const char *url, const char *key, const char *prefix)
{
    char *out = NULL;
    dims_sign_status status = (which == ENDPOINT_DIMS5)
            ? dims_sign_dims5_url(url, key, prefix, &out)
            : dims_sign_dims4_url(url, key, prefix, &out);

    if (status != DIMS_SIGN_OK) {
        return report(status);
    }

    puts(out);
    dims_sign_free(out);

    return EXIT_OK;
}

static int
run_message(const char *url, const char *prefix)
{
    char *out = NULL;
    dims_sign_status status = dims_sign_dims5_message(url, prefix, &out);

    if (status != DIMS_SIGN_OK) {
        return report(status);
    }

    puts(out);
    dims_sign_free(out);

    return EXIT_OK;
}

static int
run_verify(endpoint which, const char *url, const char *key, const char *prefix)
{
    char *signed_url = NULL;
    char *wanted;
    char *got;
    int matched;
    dims_sign_status status;

    if (prefix == NULL || *prefix == '\0') {
        prefix = (which == ENDPOINT_DIMS5) ? DIMS_SIGN_DIMS5_PREFIX
                                           : DIMS_SIGN_DIMS4_PREFIX;
    }

    status = (which == ENDPOINT_DIMS5)
            ? dims_sign_dims5_url(url, key, prefix, &signed_url)
            : dims_sign_dims4_url(url, key, prefix, &signed_url);

    if (status != DIMS_SIGN_OK) {
        return report(status);
    }

    if (which == ENDPOINT_DIMS5) {
        wanted = dims5_signature(signed_url);
        got = dims5_signature(url);
    } else {
        wanted = dims4_signature(signed_url, prefix);
        got = dims4_signature(url, prefix);
    }

    dims_sign_free(signed_url);

    if (wanted == NULL) {
        free(got);
        fputs("dims-sign: cannot read the signature it computed\n", stderr);
        return EXIT_BAD_URL;
    }

    if (got == NULL) {
        free(wanted);
        fputs("no signature\n", stdout);
        return EXIT_MISMATCH;
    }

    matched = (which == ENDPOINT_DIMS5) ? dims_sign_dims5_equal(wanted, got)
                                        : dims_sign_dims4_equal(wanted, got);

    if (matched) {
        puts("signature ok");
    } else {
        printf("signature mismatch\n  wanted %s\n  got    %s\n", wanted, got);
    }

    free(wanted);
    free(got);

    return matched ? EXIT_OK : EXIT_MISMATCH;
}

/* -- The fixture filter -------------------------------------------------- */
/*
 * Reads the signing fixtures and writes them back with signed, query,
 * message, and error set to what the library produces. The input fields are
 * case, endpoint, prefix, key, and input.
 *
 * The output field order is fixed, so a second run over the first run's
 * output produces the same bytes.
 */

typedef struct {
    char *name;
    char *endpoint;
    char *prefix;
    char *key;
    char *input;
} record;

static void
release_record(record *r)
{
    free(r->name);
    free(r->endpoint);
    free(r->prefix);
    free(r->key);
    free(r->input);
    memset(r, 0, sizeof(*r));
}

/* \n, \t, and \\ are the only escapes. */
static char *
unescape(const char *value)
{
    char *out = malloc(strlen(value) + 1);
    size_t at = 0;
    size_t i;

    if (out == NULL) {
        return NULL;
    }

    for (i = 0; value[i] != '\0'; i++) {
        if (value[i] == '\\' && value[i + 1] != '\0') {
            i++;
            switch (value[i]) {
                case 'n': out[at++] = '\n'; break;
                case 't': out[at++] = '\t'; break;
                default:  out[at++] = value[i]; break;
            }
        } else {
            out[at++] = value[i];
        }
    }

    out[at] = '\0';

    return out;
}

static void
write_field(const char *name, const char *value)
{
    const char *at;

    printf("%s\t", name);

    for (at = value; *at != '\0'; at++) {
        switch (*at) {
            case '\\': fputs("\\\\", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:   fputc(*at, stdout); break;
        }
    }

    fputc('\n', stdout);
}

static const char *
error_name(dims_sign_status status)
{
    switch (status) {
        case DIMS_SIGN_BAD_FIELD:
            return "bad-field";
        case DIMS_SIGN_BAD_ARGUMENT:
            return "bad-argument";
        default:
            return "bad-url";
    }
}

static int
write_record(const record *r)
{
    int is_dims5;
    char *signed_url = NULL;
    char *message = NULL;
    dims_sign_status status;

    if (r->name == NULL || r->endpoint == NULL || r->key == NULL ||
            r->input == NULL) {
        fprintf(stderr, "dims-sign: a record is missing a field\n");
        return EXIT_USAGE;
    }

    is_dims5 = (strcmp(r->endpoint, "dims5") == 0);
    if (!is_dims5 && strcmp(r->endpoint, "dims4") != 0) {
        fprintf(stderr, "dims-sign: %s: unknown endpoint %s\n", r->name,
                r->endpoint);
        return EXIT_USAGE;
    }

    write_field("case", r->name);
    write_field("endpoint", r->endpoint);
    write_field("prefix", (r->prefix != NULL) ? r->prefix : "");
    write_field("key", r->key);
    write_field("input", r->input);

    status = is_dims5 ? dims_sign_dims5_url(r->input, r->key, r->prefix,
                                            &signed_url)
                      : dims_sign_dims4_url(r->input, r->key, r->prefix,
                                            &signed_url);

    if (status != DIMS_SIGN_OK) {
        write_field("error", error_name(status));
        return EXIT_OK;
    }

    write_field("signed", signed_url);
    dims_sign_free(signed_url);

    if (is_dims5) {
        const char *query = strchr(r->input, '?');
        char *canonical = NULL;

        if (dims_sign_canonical_query((query != NULL) ? query + 1 : NULL,
                                      &canonical) != DIMS_SIGN_OK) {
            return EXIT_BAD_URL;
        }

        write_field("query", canonical);
        dims_sign_free(canonical);

        status = dims_sign_dims5_message(r->input, r->prefix, &message);
    } else {
        status = dims_sign_dims4_message(r->input, r->key, r->prefix, &message);
    }

    if (status != DIMS_SIGN_OK) {
        return report(status);
    }

    write_field("message", message);
    dims_sign_free(message);

    return EXIT_OK;
}

static int
set_field(record *r, const char *name, char *value)
{
    if (strcmp(name, "case") == 0) {
        free(r->name);
        r->name = value;
    } else if (strcmp(name, "endpoint") == 0) {
        free(r->endpoint);
        r->endpoint = value;
    } else if (strcmp(name, "prefix") == 0) {
        free(r->prefix);
        r->prefix = value;
    } else if (strcmp(name, "key") == 0) {
        free(r->key);
        r->key = value;
    } else if (strcmp(name, "input") == 0) {
        free(r->input);
        r->input = value;
    } else if (strcmp(name, "signed") == 0 || strcmp(name, "query") == 0 ||
               strcmp(name, "message") == 0 || strcmp(name, "error") == 0) {
        /* The library writes these. */
        free(value);
    } else {
        free(value);
        fprintf(stderr, "dims-sign: unknown field %s\n", name);
        return 0;
    }

    return 1;
}

static int
run_fixture(void)
{
    record current;
    int open = 0;
    int result = EXIT_OK;
    char *line;

    memset(&current, 0, sizeof(current));

    while ((line = read_line(stdin)) != NULL) {
        char *tab;
        char *value;

        if (*line == '\0') {
            if (open) {
                result = write_record(&current);
                release_record(&current);
                open = 0;
                if (result != EXIT_OK) {
                    free(line);
                    return result;
                }
            }

            puts("");
            free(line);
            continue;
        }

        if (*line == '#') {
            puts(line);
            free(line);
            continue;
        }

        tab = strchr(line, '\t');
        if (tab == NULL) {
            fprintf(stderr, "dims-sign: a line has no tab: %s\n", line);
            free(line);
            release_record(&current);
            return EXIT_USAGE;
        }

        *tab = '\0';
        value = unescape(tab + 1);
        if (value == NULL || !set_field(&current, line, value)) {
            free(line);
            release_record(&current);
            return EXIT_USAGE;
        }

        open = 1;
        free(line);
    }

    if (open) {
        result = write_record(&current);
    }

    release_record(&current);

    return result;
}

/* -- The command -------------------------------------------------------- */

int
main(int argc, char **argv)
{
    endpoint which = ENDPOINT_NONE;
    mode how = MODE_SIGN;
    const char *key_file = NULL;
    const char *prefix = NULL;
    const char *url = NULL;
    char *key = NULL;
    int result;
    int i;

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--dims4") == 0) {
            which = ENDPOINT_DIMS4;
        } else if (strcmp(arg, "--dims5") == 0) {
            which = ENDPOINT_DIMS5;
        } else if (strcmp(arg, "--message") == 0) {
            how = MODE_MESSAGE;
        } else if (strcmp(arg, "--verify") == 0) {
            how = MODE_VERIFY;
        } else if (strcmp(arg, "--fixture") == 0) {
            how = MODE_FIXTURE;
        } else if (strcmp(arg, "--key-file") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(arg, "--prefix") == 0 && i + 1 < argc) {
            prefix = argv[++i];
        } else if (strcmp(arg, "--help") == 0) {
            usage(stdout);
            return EXIT_OK;
        } else if (*arg == '-') {
            fprintf(stderr, "dims-sign: unknown option %s\n", arg);
            usage(stderr);
            return EXIT_USAGE;
        } else if (url == NULL) {
            url = arg;
        } else {
            fputs("dims-sign: one URL at a time\n", stderr);
            return EXIT_USAGE;
        }
    }

    if (how == MODE_FIXTURE) {
        return run_fixture();
    }

    if (which == ENDPOINT_NONE || url == NULL) {
        usage(stderr);
        return EXIT_USAGE;
    }

    if (how == MODE_MESSAGE) {
        if (which == ENDPOINT_DIMS4) {
            fputs("dims-sign: --message needs --dims5. A /dims4/ message holds "
                  "the client secret.\n", stderr);
            return EXIT_USAGE;
        }

        return run_message(url, prefix);
    }

    if (key_file != NULL) {
        key = read_key_file(key_file);
        if (key == NULL) {
            return EXIT_USAGE;
        }
    } else {
        const char *from_environment = getenv("DIMS_SIGNING_KEY");

        if (from_environment == NULL || *from_environment == '\0') {
            fputs("dims-sign: no key. Pass --key-file, or set "
                  "DIMS_SIGNING_KEY.\n", stderr);
            return EXIT_USAGE;
        }

        key = malloc(strlen(from_environment) + 1);
        if (key == NULL) {
            return EXIT_USAGE;
        }

        strcpy(key, from_environment);
    }

    result = (how == MODE_VERIFY) ? run_verify(which, url, key, prefix)
                                  : run_sign(which, url, key, prefix);

    free(key);

    return result;
}
