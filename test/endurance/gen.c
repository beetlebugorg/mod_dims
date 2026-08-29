/*
 * Building one soak request.
 *
 * The seeded generator makes every choice: the endpoint, the source, the
 * command chain, each argument, the query, and the mutation applied after
 * signing. A run with the same seed builds the same requests.
 *
 * Each plan also holds the expected result. It is a firm expectation only
 * where the contract is firm. The report counts the result of a mutation whose
 * outcome depends on a configuration setting.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "soak.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -- The generator ------------------------------------------------------ */

void
dims_rng_seed(dims_rng *rng, uint64_t seed)
{
    rng->state = seed;
}

uint64_t
dims_rng_next(dims_rng *rng)
{
    uint64_t z = (rng->state += 0x9E3779B97F4A7C15ULL);

    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;

    return z ^ (z >> 31);
}

uint32_t
dims_rng_below(dims_rng *rng, uint32_t bound)
{
    return (bound == 0) ? 0 : (uint32_t) (dims_rng_next(rng) % bound);
}

int
dims_rng_chance(dims_rng *rng, int percent)
{
    return (int) dims_rng_below(rng, 100) < percent;
}

/* -- A growable string --------------------------------------------------- */

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} buffer;

static void
buffer_init(buffer *b)
{
    b->data = malloc(256);
    b->length = 0;
    b->capacity = 256;
    if (b->data != NULL) {
        b->data[0] = '\0';
    }
}

static void
buffer_add(buffer *b, const char *text)
{
    size_t add;

    if (b->data == NULL || text == NULL) {
        return;
    }

    add = strlen(text);

    if (b->length + add + 1 > b->capacity) {
        size_t next = b->capacity;
        char *grown;

        while (next < b->length + add + 1) {
            next *= 2;
        }

        grown = realloc(b->data, next);
        if (grown == NULL) {
            return;
        }

        b->data = grown;
        b->capacity = next;
    }

    memcpy(b->data + b->length, text, add + 1);
    b->length += add;
}

/* Formats into a scratch buffer, then appends. Never takes caller data as a
 * format string. */
static void
buffer_addf(buffer *b, const char *format, ...)
{
    char scratch[512];
    va_list arguments;

    va_start(arguments, format);
    vsnprintf(scratch, sizeof(scratch), format, arguments);
    va_end(arguments);

    buffer_add(b, scratch);
}

static char *
buffer_take(buffer *b)
{
    char *data = b->data;

    b->data = NULL;
    b->length = 0;
    b->capacity = 0;

    return data;
}

static char *
duplicate(const char *text)
{
    char *copy = malloc(strlen(text) + 1);

    if (copy != NULL) {
        memcpy(copy, text, strlen(text) + 1);
    }

    return copy;
}

static char *
formatted(const char *format, ...)
{
    char scratch[512];
    va_list arguments;

    va_start(arguments, format);
    vsnprintf(scratch, sizeof(scratch), format, arguments);
    va_end(arguments);

    return duplicate(scratch);
}

/* -- Arguments an operation reads ---------------------------------------- */

static char *
argument_geometry(dims_rng *rng)
{
    unsigned width = 8 + dims_rng_below(rng, 1800);
    unsigned height = 8 + dims_rng_below(rng, 1800);

    switch (dims_rng_below(rng, 8)) {
        case 0: return formatted("%ux%u", width, height);
        case 1: return formatted("%u", width);
        case 2: return formatted("x%u", height);
        case 3: return formatted("%ux%u!", width, height);
        case 4: return formatted("%ux%u>", width, height);
        case 5: return formatted("%ux%u<", width, height);
        case 6: return formatted("%u%%", 5 + dims_rng_below(rng, 195));
        default: return formatted("%ux%u^", width, height);
    }
}

static char *
argument_crop(dims_rng *rng)
{
    unsigned width = 8 + dims_rng_below(rng, 1400);
    unsigned height = 8 + dims_rng_below(rng, 1400);
    unsigned x = dims_rng_below(rng, 600);
    unsigned y = dims_rng_below(rng, 600);

    switch (dims_rng_below(rng, 5)) {
        case 0: return formatted("%ux%u+%u+%u", width, height, x, y);
        case 1: return formatted("%ux%u", width, height);
        case 2: return formatted("%u%%x%u%%+0+0", 10 + dims_rng_below(rng, 80),
                                 10 + dims_rng_below(rng, 80));
        case 3: return formatted("%ux%u-%u-%u", width, height, x, y);
        /* A client that escapes the plus as a space. The module turns it
         * back, so this has to sign and answer like the form above. */
        default: return formatted("%ux%u %u %u", width, height, x, y);
    }
}

static char *
argument_thumbnail(dims_rng *rng)
{
    unsigned width = 8 + dims_rng_below(rng, 1200);
    unsigned height = 8 + dims_rng_below(rng, 1200);

    switch (dims_rng_below(rng, 3)) {
        case 0: return formatted("%ux%u", width, height);
        case 1: return formatted("%u", width);
        default: return formatted("x%u", height);
    }
}

static char *
argument_rotate(dims_rng *rng)
{
    if (dims_rng_chance(rng, 60)) {
        static const int quarters[] = { 0, 90, 180, 270, -90, -180 };

        return formatted("%d", quarters[dims_rng_below(rng, 6)]);
    }

    return formatted("%u", dims_rng_below(rng, 360));
}

static char *
argument_quality(dims_rng *rng)
{
    return formatted("%u", 1 + dims_rng_below(rng, 100));
}

static char *
argument_sepia(dims_rng *rng)
{
    return formatted("0.%02u", dims_rng_below(rng, 100));
}

static char *
argument_sharpen(dims_rng *rng)
{
    return formatted("0x%u.%u", dims_rng_below(rng, 4), dims_rng_below(rng, 10));
}

static char *
argument_brightness(dims_rng *rng)
{
    return formatted("%dx%d", (int) dims_rng_below(rng, 201) - 100,
                     (int) dims_rng_below(rng, 201) - 100);
}

static char *
argument_format(dims_rng *rng)
{
    static const char *const formats[] = { "jpg", "png", "gif", "webp", "tiff" };

    return duplicate(formats[dims_rng_below(rng, 5)]);
}

static char *
argument_flipflop(dims_rng *rng)
{
    return duplicate(dims_rng_chance(rng, 50) ? "horizontal" : "vertical");
}

static char *
argument_boolean(dims_rng *rng)
{
    return duplicate(dims_rng_chance(rng, 70) ? "true" : "false");
}

static char *
argument_watermark(dims_rng *rng)
{
    static const char *const gravity[] = {
        "nw", "n", "ne", "w", "c", "e", "sw", "s", "se"
    };

    return formatted("0.%u,0.%u,%s",
                     1 + dims_rng_below(rng, 9),
                     1 + dims_rng_below(rng, 9),
                     gravity[dims_rng_below(rng, 9)]);
}

/*
 * Arguments no operation reads. A slash separates two commands and a null byte
 * does not survive the request line, so this table holds neither.
 */
static char *
argument_hostile(dims_rng *rng)
{
    static const char *const hostile[] = {
        "", "0", "-1", "0x0", "-100x-100", "99999999x99999999",
        "1e400", "nan", "inf", "abc", "..", "....", "!@#$^&*()",
        "999999999999999999999999", "-0", "+", "x", "0x", "x0",
        "100x100!!!", "50%%", ",,,", "1,2", "a,b,c", "1.0,1.0,zz",
        "0,0,0", "<script>", "'\"", "  ", "+++", "1x1x1x1", "0.0.0.0",
        "NULL", "true;false", "{0}", "[1]", "\xc3\xa9\xc3\xa9",
        "0x-1", "1//2", "-2147483648", "2147483648", "4294967296",
        "0.0000000001", "1e-400", "0b101", "0o777", "1_000"
    };
    static const size_t count = sizeof(hostile) / sizeof(hostile[0]);

    /* One argument in eight is long instead of malformed. A long argument
     * tests the buffer sizes, and a malformed one tests the parser. */
    if (dims_rng_chance(rng, 12)) {
        size_t length = 256 + dims_rng_below(rng, 3840);
        char *out = malloc(length + 1);

        if (out != NULL) {
            memset(out, 'A', length);
            out[length] = '\0';
        }

        return out;
    }

    return duplicate(hostile[dims_rng_below(rng, (uint32_t) count)]);
}

typedef struct {
    const char *name;
    char *(*argument)(dims_rng *);
    int weight;
} operation;

/*
 * Every operation the module registers. The weight is how often a production
 * request asks for it. resize, crop, thumbnail, format, and quality take most
 * of the traffic. The rest run less often.
 */
static const operation operations[] = {
    { "resize",           argument_geometry,   22 },
    { "thumbnail",        argument_thumbnail,  12 },
    { "crop",             argument_crop,       12 },
    { "format",           argument_format,     11 },
    { "quality",          argument_quality,    11 },
    { "strip",            argument_boolean,     7 },
    { "sharpen",          argument_sharpen,     4 },
    { "rotate",           argument_rotate,      4 },
    { "brightness",       argument_brightness,  3 },
    { "grayscale",        argument_boolean,     3 },
    { "flipflop",         argument_flipflop,    3 },
    { "sepia",            argument_sepia,       2 },
    { "invert",           argument_boolean,     2 },
    { "autolevel",        argument_boolean,     2 },
    { "legacy_crop",      argument_crop,        2 },
    { "legacy_thumbnail", argument_thumbnail,   2 },
    { "watermark",        argument_watermark,   2 }
};

static const size_t operation_count =
        sizeof(operations) / sizeof(operations[0]);

static const operation *
pick_operation(dims_rng *rng)
{
    int total = 0;
    int roll;
    size_t i;

    for (i = 0; i < operation_count; i++) {
        total += operations[i].weight;
    }

    roll = (int) dims_rng_below(rng, (uint32_t) total);

    for (i = 0; i < operation_count; i++) {
        roll -= operations[i].weight;
        if (roll < 0) {
            return &operations[i];
        }
    }

    return &operations[0];
}

/* -- Names --------------------------------------------------------------- */

const char *
dims_endpoint_name(dims_endpoint endpoint)
{
    switch (endpoint) {
        case DIMS_ENDPOINT_DIMS3: return "dims3";
        case DIMS_ENDPOINT_DIMS4: return "dims4";
        default:                  return "dims5";
    }
}

const char *
dims_tamper_name(dims_tamper tamper)
{
    switch (tamper) {
        case DIMS_TAMPER_NONE:              return "none";
        case DIMS_TAMPER_FLIP_SIGNATURE:    return "flip-signature";
        case DIMS_TAMPER_SHORT_SIGNATURE:   return "short-signature";
        case DIMS_TAMPER_SIX_SIGNATURE:     return "six-signature";
        case DIMS_TAMPER_UPPER_SIGNATURE:   return "upper-signature";
        case DIMS_TAMPER_NO_SIGNATURE:      return "no-signature";
        case DIMS_TAMPER_EXPIRED:           return "expired";
        case DIMS_TAMPER_FAR_FUTURE:        return "far-future";
        case DIMS_TAMPER_WRONG_CLIENT:      return "wrong-client";
        case DIMS_TAMPER_REWRITE_COMMANDS:  return "rewrite-commands";
        case DIMS_TAMPER_SWAP_URL:          return "swap-url";
        case DIMS_TAMPER_EXTRA_PARAM:       return "extra-param";
        case DIMS_TAMPER_REORDER_QUERY:     return "reorder-query";
        case DIMS_TAMPER_DUPLICATE_URL:     return "duplicate-url";
        case DIMS_TAMPER_CONTROL_CHARACTER: return "control-character";
        default:                            return "unknown";
    }
}

const char *
dims_expect_name(dims_expect expect)
{
    switch (expect) {
        case DIMS_EXPECT_IMAGE:  return "image";
        case DIMS_EXPECT_REFUSE: return "refuse";
        default:                 return "any";
    }
}

/* -- Building the request ------------------------------------------------ */

/* The expiry a signed /dims4/ request carries when it is not being aged out. */
#define SOAK_EXPIRES "2147483647"

/*
 * The /dims4/ signature covers the commands as httpd hands them over, and the
 * module turns each space back into the plus a client escaped. The caller
 * frees.
 */
static char *
plus_for_space(const char *text)
{
    char *copy = duplicate(text);
    char *at;

    for (at = copy; at != NULL && *at != '\0'; at++) {
        if (*at == ' ') {
            *at = '+';
        }
    }

    return copy;
}

/* One query parameter, already encoded the way it travels. */
typedef struct {
    const char *name;
    char *value;
} parameter;

#define SOAK_MAX_PARAMETERS 8

static void
add_parameter(parameter *list, size_t *count, const char *name, char *value)
{
    if (value == NULL) {
        return;
    }

    /* A value the list has no room for is freed here. A run sends millions of
     * requests, so a dropped value would leak the whole way through. */
    if (*count >= SOAK_MAX_PARAMETERS) {
        free(value);
        return;
    }

    list[*count].name = name;
    list[*count].value = value;
    (*count)++;
}

/*
 * The query /dims5/ signs: every parameter but sig, url, eurl, _keys, and
 * download, sorted by name, each side percent-encoded. The caller frees.
 */
static char *
canonical_query(const parameter *list, size_t count)
{
    size_t order[SOAK_MAX_PARAMETERS];
    size_t chosen = 0;
    size_t i;
    size_t j;
    buffer out;

    for (i = 0; i < count; i++) {
        const char *name = list[i].name;

        if (strcmp(name, "sig") == 0 || strcmp(name, "url") == 0 ||
                strcmp(name, "eurl") == 0 || strcmp(name, "_keys") == 0 ||
                strcmp(name, "download") == 0) {
            continue;
        }

        order[chosen++] = i;
    }

    for (i = 1; i < chosen; i++) {
        size_t hold = order[i];

        for (j = i; j > 0 &&
                strcmp(list[order[j - 1]].name, list[hold].name) > 0; j--) {
            order[j] = order[j - 1];
        }
        order[j] = hold;
    }

    buffer_init(&out);

    for (i = 0; i < chosen; i++) {
        char *name = dims_escape(list[order[i]].name);

        if (i > 0) {
            buffer_add(&out, "&");
        }
        buffer_add(&out, name != NULL ? name : "");
        buffer_add(&out, "=");
        /* The value already travels encoded, and the module decodes it and
         * encodes it again, which lands on the same string. */
        buffer_add(&out, list[order[i]].value);
        free(name);
    }

    return buffer_take(&out);
}

/* The value of each parameter _keys names, concatenated in _keys order. The
 * module reads them out of the raw query, so they are still encoded. */
static char *
keyed_values(const parameter *list, size_t count, const char *keys)
{
    buffer out;
    size_t i;

    buffer_init(&out);

    if (keys != NULL) {
        for (i = 0; i < count; i++) {
            if (strcmp(list[i].name, keys) == 0) {
                buffer_add(&out, list[i].value);
                break;
            }
        }
    }

    return buffer_take(&out);
}

/*
 * Changes one hexadecimal character, within the first compared bytes.
 *
 * /dims4/ compares six characters, so a change past the sixth leaves a
 * signature the module still accepts. /dims5/ compares the whole digest.
 */
static char *
flip_one_hexadecimal(const char *signature, dims_rng *rng, size_t compared)
{
    char *copy = duplicate(signature);
    size_t length;
    size_t at;

    if (copy == NULL) {
        return NULL;
    }

    length = strlen(copy);
    if (length == 0) {
        return copy;
    }

    if (compared > 0 && compared < length) {
        length = compared;
    }

    at = dims_rng_below(rng, (uint32_t) length);
    copy[at] = (copy[at] == '0') ? '1' : '0';

    return copy;
}

static char *
upper_case(const char *text)
{
    char *copy = duplicate(text);
    char *at;

    for (at = copy; at != NULL && *at != '\0'; at++) {
        if (*at >= 'a' && *at <= 'z') {
            *at = (char) (*at - 'a' + 'A');
        }
    }

    return copy;
}

/* Changes one digit in the commands, so the path no longer matches what was
 * signed. */
static char *
rewrite_commands(const char *commands)
{
    char *copy = duplicate(commands);
    char *at;

    for (at = copy; at != NULL && *at != '\0'; at++) {
        if (*at >= '0' && *at <= '8') {
            *at = (char) (*at + 1);
            return copy;
        }
        if (*at == '9') {
            *at = '0';
            return copy;
        }
    }

    /* No digit to move, so add a command instead. */
    free(copy);

    return formatted("%s/rotate/90", commands);
}

/* Which mutations each endpoint can carry. */
static dims_tamper
pick_tamper(dims_endpoint endpoint, dims_rng *rng)
{
    static const dims_tamper for_dims3[] = {
        DIMS_TAMPER_WRONG_CLIENT, DIMS_TAMPER_REORDER_QUERY,
        DIMS_TAMPER_EXTRA_PARAM, DIMS_TAMPER_DUPLICATE_URL
    };
    static const dims_tamper for_dims4[] = {
        DIMS_TAMPER_FLIP_SIGNATURE, DIMS_TAMPER_SHORT_SIGNATURE,
        DIMS_TAMPER_SIX_SIGNATURE, DIMS_TAMPER_UPPER_SIGNATURE,
        DIMS_TAMPER_NO_SIGNATURE, DIMS_TAMPER_EXPIRED,
        DIMS_TAMPER_FAR_FUTURE, DIMS_TAMPER_WRONG_CLIENT,
        DIMS_TAMPER_REWRITE_COMMANDS, DIMS_TAMPER_SWAP_URL,
        DIMS_TAMPER_EXTRA_PARAM, DIMS_TAMPER_REORDER_QUERY,
        DIMS_TAMPER_DUPLICATE_URL, DIMS_TAMPER_CONTROL_CHARACTER
    };
    static const dims_tamper for_dims5[] = {
        DIMS_TAMPER_FLIP_SIGNATURE, DIMS_TAMPER_SHORT_SIGNATURE,
        DIMS_TAMPER_SIX_SIGNATURE, DIMS_TAMPER_UPPER_SIGNATURE,
        DIMS_TAMPER_NO_SIGNATURE, DIMS_TAMPER_REWRITE_COMMANDS,
        DIMS_TAMPER_SWAP_URL, DIMS_TAMPER_EXTRA_PARAM,
        DIMS_TAMPER_REORDER_QUERY, DIMS_TAMPER_DUPLICATE_URL,
        DIMS_TAMPER_CONTROL_CHARACTER
    };

    /* Most requests are well formed, which is what a production server sees.
     * A run of nothing but mutations measures a different server. */
    if (dims_rng_chance(rng, 72)) {
        return DIMS_TAMPER_NONE;
    }

    switch (endpoint) {
        case DIMS_ENDPOINT_DIMS3:
            return for_dims3[dims_rng_below(rng, 4)];
        case DIMS_ENDPOINT_DIMS4:
            return for_dims4[dims_rng_below(rng, 14)];
        default:
            return for_dims5[dims_rng_below(rng, 11)];
    }
}

/*
 * The expected result.
 *
 * A mutation that must never return an image returns "refuse". A mutation whose
 * result depends on a configuration setting returns "any", and the report
 * counts each result it saw.
 *
 * uncertain covers the requests where the module may answer either way: an
 * argument outside what the operation reads, and an SVG source with no format
 * command.
 */
static dims_expect
expectation(dims_endpoint endpoint, dims_tamper tamper,
            dims_source_class klass, int uncertain)
{
    switch (tamper) {
        /* No configuration accepts any of these. */
        case DIMS_TAMPER_FLIP_SIGNATURE:
        case DIMS_TAMPER_SHORT_SIGNATURE:
        case DIMS_TAMPER_NO_SIGNATURE:
        case DIMS_TAMPER_EXPIRED:
        case DIMS_TAMPER_WRONG_CLIENT:
        case DIMS_TAMPER_REWRITE_COMMANDS:
        case DIMS_TAMPER_SWAP_URL:
            if (endpoint != DIMS_ENDPOINT_DIMS3) {
                return DIMS_EXPECT_REFUSE;
            }
            /* /dims3/ is not signed, so only the client id means anything. */
            if (tamper == DIMS_TAMPER_WRONG_CLIENT) {
                return DIMS_EXPECT_REFUSE;
            }
            break;

        /* /dims5/ compares the whole digest, and it signs every parameter. */
        case DIMS_TAMPER_SIX_SIGNATURE:
        case DIMS_TAMPER_UPPER_SIGNATURE:
        case DIMS_TAMPER_EXTRA_PARAM:
        case DIMS_TAMPER_CONTROL_CHARACTER:
            if (endpoint == DIMS_ENDPOINT_DIMS5) {
                return DIMS_EXPECT_REFUSE;
            }
            return DIMS_EXPECT_ANY;

        /* Sorting the query is part of the signature, so the order a client
         * sends cannot change the answer. */
        case DIMS_TAMPER_REORDER_QUERY:
            break;

        case DIMS_TAMPER_FAR_FUTURE:
        case DIMS_TAMPER_DUPLICATE_URL:
            return DIMS_EXPECT_ANY;

        default:
            break;
    }

    if (klass == DIMS_CLASS_REJECT) {
        return DIMS_EXPECT_REFUSE;
    }

    if (klass == DIMS_CLASS_EITHER || uncertain) {
        return DIMS_EXPECT_ANY;
    }

    return DIMS_EXPECT_IMAGE;
}

static const dims_source *
pick_source(const dims_world *world, dims_rng *rng, dims_source_class *klass)
{
    const dims_corpus *corpus = world->corpus;
    int roll = (int) dims_rng_below(rng, 100);
    const size_t *list;
    size_t count;

    if (roll < 78 && corpus->image_count > 0) {
        list = corpus->image;
        count = corpus->image_count;
    } else if (roll < 90 && corpus->either_count > 0) {
        list = corpus->either;
        count = corpus->either_count;
    } else if (corpus->reject_count > 0) {
        list = corpus->reject;
        count = corpus->reject_count;
    } else if (corpus->image_count > 0) {
        list = corpus->image;
        count = corpus->image_count;
    } else {
        list = NULL;
        count = 0;
    }

    if (count == 0) {
        *klass = DIMS_CLASS_EITHER;
        return &corpus->items[0];
    }

    {
        const dims_source *source =
                &corpus->items[list[dims_rng_below(rng, (uint32_t) count)]];

        *klass = source->klass;

        return source;
    }
}

void
dims_plan_make(dims_plan *plan, const dims_world *world, dims_rng *rng,
               uint64_t sequence)
{
    const dims_corpus *corpus = world->corpus;
    const dims_source *source;
    const dims_source *signed_source;
    dims_source_class klass;
    dims_endpoint endpoint;
    dims_tamper tamper;
    parameter parameters[SOAK_MAX_PARAMETERS];
    size_t parameter_count = 0;
    buffer commands;
    buffer path;
    char *command_string;
    char *escaped_commands;
    char *image_url;
    char *signed_url;
    char *signature = NULL;
    const char *client;
    const char *expires = SOAK_EXPIRES;
    int wants_overlay = 0;
    int hostile = 0;
    int svg_without_format = 0;
    int roll;
    int length;
    int i;

    memset(plan, 0, sizeof(*plan));
    plan->seq = sequence;

    /* The endpoint. /dims3/ is unsigned and still in service, so it keeps a
     * share of the traffic. */
    roll = (int) dims_rng_below(rng, 100);
    endpoint = (roll < 14) ? DIMS_ENDPOINT_DIMS3
             : (roll < 57) ? DIMS_ENDPOINT_DIMS4
             : DIMS_ENDPOINT_DIMS5;

    source = pick_source(world, rng, &klass);
    signed_source = source;

    tamper = pick_tamper(endpoint, rng);

    /* The command chain. */
    buffer_init(&commands);
    length = 1 + (int) dims_rng_below(rng, 6);

    for (i = 0; i < length; i++) {
        const operation *op = pick_operation(rng);
        char *argument;

        if (strcmp(op->name, "watermark") == 0) {
            if (wants_overlay) {
                continue;
            }
            wants_overlay = 1;
        }

        /* One argument in eight is outside what the operation reads. */
        if (dims_rng_chance(rng, 12)) {
            argument = argument_hostile(rng);
            hostile = 1;
        } else {
            argument = op->argument(rng);
        }

        if (argument == NULL) {
            continue;
        }

        if (commands.length > 0) {
            buffer_add(&commands, "/");
        }
        buffer_add(&commands, op->name);
        buffer_add(&commands, "/");
        buffer_add(&commands, argument);

        free(argument);
    }

    /*
     * The module answers with the source format when no format command names
     * another, and it cannot write SVG. An SVG source therefore needs a raster
     * format before the response can be an image. Most of them get one. The
     * rest run the path without one, where either answer is allowed.
     */
    if (source->format != NULL &&
            (strcmp(source->format, "SVG") == 0 ||
             strcmp(source->format, "MSVG") == 0)) {
        if (dims_rng_chance(rng, 80)) {
            char *raster = argument_format(rng);

            if (commands.length > 0) {
                buffer_add(&commands, "/");
            }
            buffer_add(&commands, "format/");
            buffer_add(&commands, raster);
            free(raster);
        } else {
            svg_without_format = 1;
        }
    }

    if (tamper == DIMS_TAMPER_CONTROL_CHARACTER) {
        buffer_add(&commands, "\n");
    }

    command_string = buffer_take(&commands);
    if (command_string == NULL) {
        command_string = duplicate("resize/100x100");
    }

    plan->commands = duplicate(command_string);

    /* The source URL, and the one the signature covers when they differ. */
    image_url = formatted("%s/%s", world->origin, source->name);

    if (tamper == DIMS_TAMPER_SWAP_URL && corpus->count > 1) {
        signed_source = &corpus->items[dims_rng_below(rng,
                (uint32_t) corpus->count)];
        if (signed_source == source) {
            signed_source = &corpus->items[(source == corpus->items) ? 1 : 0];
        }
    }

    signed_url = formatted("%s/%s", world->origin, signed_source->name);

    /* The query.
     *
     * eurl replaces the url parameter, so a mutation that rewrites url has
     * nothing to rewrite and the request stays valid. */
    if (world->use_eurl && dims_rng_chance(rng, 12) &&
            tamper != DIMS_TAMPER_SWAP_URL &&
            tamper != DIMS_TAMPER_DUPLICATE_URL) {
        unsigned char key[16];
        char *eurl = NULL;

        if (endpoint == DIMS_ENDPOINT_DIMS5) {
            if (dims_key_hkdf(world->signing_key, key)) {
                eurl = dims_eurl_gcm(key, signed_url, rng);
            }
        } else if (endpoint == DIMS_ENDPOINT_DIMS4) {
            if (dims_key_sha1(world->secret, key)) {
                eurl = world->eurl_ecb ? dims_eurl_ecb(key, signed_url)
                                       : dims_eurl_gcm(key, signed_url, rng);
            }
        }

        /* The base64 travels unescaped. The module reads the parameter without
         * decoding it, so a plus stays a plus. */
        if (eurl != NULL) {
            add_parameter(parameters, &parameter_count, "eurl", eurl);
        } else {
            add_parameter(parameters, &parameter_count, "url",
                          dims_escape(signed_url));
        }
    } else {
        add_parameter(parameters, &parameter_count, "url", dims_escape(signed_url));
    }

    if (wants_overlay) {
        add_parameter(parameters, &parameter_count, "overlay",
                      dims_escape(world->overlay));
        if (endpoint != DIMS_ENDPOINT_DIMS5) {
            add_parameter(parameters, &parameter_count, "_keys",
                          duplicate("overlay"));
        }
    }

    if (dims_rng_chance(rng, 5)) {
        add_parameter(parameters, &parameter_count, "download", duplicate("1"));
    }

    /* Sign. */
    client = (tamper == DIMS_TAMPER_WRONG_CLIENT) ? "nosuchclient" : world->client;

    if (tamper == DIMS_TAMPER_EXPIRED) {
        expires = "1000000000";
    } else if (tamper == DIMS_TAMPER_FAR_FUTURE) {
        expires = "4102444800";
    }

    if (endpoint == DIMS_ENDPOINT_DIMS4) {
        char *with_slash = formatted("%s/", command_string);
        char *as_signed = plus_for_space(with_slash);
        char *keyed = keyed_values(parameters, parameter_count,
                                   wants_overlay ? "overlay" : NULL);
        buffer message;

        buffer_init(&message);
        buffer_add(&message, expires);
        buffer_add(&message, world->secret);
        buffer_add(&message, as_signed);
        buffer_add(&message, signed_url);
        buffer_add(&message, keyed);

        signature = dims_md5_hex(message.data != NULL ? message.data : "");

        free(buffer_take(&message));
        free(with_slash);
        free(as_signed);
        free(keyed);
    } else if (endpoint == DIMS_ENDPOINT_DIMS5) {
        char *with_slash = formatted("%s/", command_string);
        char *query = canonical_query(parameters, parameter_count);
        buffer message;

        buffer_init(&message);
        buffer_add(&message, with_slash);
        buffer_add(&message, "\n");
        buffer_add(&message, signed_url);
        buffer_add(&message, "\n");
        buffer_add(&message, query != NULL ? query : "");

        signature = dims_hmac_sha256_hex(world->signing_key,
                message.data != NULL ? message.data : "");

        free(buffer_take(&message));
        free(with_slash);
        free(query);
    }

    /* Mutate what was signed. */
    if (signature != NULL) {
        char *changed = NULL;

        switch (tamper) {
            case DIMS_TAMPER_FLIP_SIGNATURE:
                changed = flip_one_hexadecimal(signature, rng,
                        (endpoint == DIMS_ENDPOINT_DIMS4) ? 6 : 0);
                break;
            case DIMS_TAMPER_SHORT_SIGNATURE:
                changed = duplicate(signature);
                if (changed != NULL && strlen(changed) > 5) {
                    changed[5] = '\0';
                }
                break;
            case DIMS_TAMPER_SIX_SIGNATURE:
                changed = duplicate(signature);
                if (changed != NULL && strlen(changed) > 6) {
                    changed[6] = '\0';
                }
                break;
            case DIMS_TAMPER_UPPER_SIGNATURE:
                changed = upper_case(signature);
                break;
            default:
                break;
        }

        if (changed != NULL) {
            free(signature);
            signature = changed;
        }
    }

    if (tamper == DIMS_TAMPER_REWRITE_COMMANDS) {
        char *rewritten = rewrite_commands(command_string);

        free(command_string);
        command_string = rewritten;
    }

    if (tamper == DIMS_TAMPER_SWAP_URL) {
        size_t i2;

        /* The signature covers the other source. Send this one. */
        for (i2 = 0; i2 < parameter_count; i2++) {
            if (strcmp(parameters[i2].name, "url") == 0) {
                free(parameters[i2].value);
                parameters[i2].value = dims_escape(image_url);
            }
        }
    }

    if (tamper == DIMS_TAMPER_EXTRA_PARAM) {
        add_parameter(parameters, &parameter_count, "cb",
                      formatted("%u", (unsigned) dims_rng_below(rng, 100000)));
    }

    if (tamper == DIMS_TAMPER_DUPLICATE_URL && corpus->count > 1) {
        /* An earlier url the signature does not cover. The module reads the
         * last one, so the request still has to verify. */
        size_t other = dims_rng_below(rng, (uint32_t) corpus->count);
        char *decoy = formatted("%s/%s", world->origin,
                                corpus->items[other].name);
        parameter shifted[SOAK_MAX_PARAMETERS];
        size_t i2;

        if (parameter_count + 1 <= SOAK_MAX_PARAMETERS) {
            shifted[0].name = "url";
            shifted[0].value = dims_escape(decoy);
            for (i2 = 0; i2 < parameter_count; i2++) {
                shifted[i2 + 1] = parameters[i2];
            }
            parameter_count++;
            memcpy(parameters, shifted, parameter_count * sizeof(parameter));
        }

        free(decoy);
    }

    if (signature != NULL && tamper != DIMS_TAMPER_NO_SIGNATURE &&
            endpoint == DIMS_ENDPOINT_DIMS5) {
        add_parameter(parameters, &parameter_count, "sig", duplicate(signature));
    }

    /* Assemble the path. */
    escaped_commands = dims_escape_path(command_string);

    buffer_init(&path);

    if (endpoint == DIMS_ENDPOINT_DIMS3) {
        buffer_addf(&path, "/dims3/%s/", client);
        buffer_add(&path, escaped_commands != NULL ? escaped_commands : "");
        buffer_add(&path, "/");
    } else if (endpoint == DIMS_ENDPOINT_DIMS4) {
        buffer_add(&path, "/dims4/");
        buffer_add(&path, client);
        buffer_add(&path, "/");
        if (tamper != DIMS_TAMPER_NO_SIGNATURE) {
            buffer_add(&path, signature != NULL ? signature : "0");
            buffer_add(&path, "/");
        }
        buffer_add(&path, expires);
        buffer_add(&path, "/");
        buffer_add(&path, escaped_commands != NULL ? escaped_commands : "");
        buffer_add(&path, "/");
    } else {
        buffer_add(&path, "/dims5/");
        buffer_add(&path, escaped_commands != NULL ? escaped_commands : "");
        buffer_add(&path, "/");
    }

    buffer_add(&path, "?");

    for (i = 0; i < (int) parameter_count; i++) {
        size_t at = (tamper == DIMS_TAMPER_REORDER_QUERY)
                ? parameter_count - 1 - (size_t) i
                : (size_t) i;

        if (i > 0) {
            buffer_add(&path, "&");
        }
        buffer_add(&path, parameters[at].name);
        buffer_add(&path, "=");
        buffer_add(&path, parameters[at].value);
    }

    plan->path = buffer_take(&path);
    plan->endpoint = endpoint;
    plan->tamper = tamper;
    plan->source = source->name;
    plan->hostile_argument = hostile;
    plan->conditional = dims_rng_chance(rng, 3);
    plan->expect = expectation(endpoint, tamper, klass,
                               hostile || svg_without_format);

    /* A conditional request may answer 304, which is neither an image nor a
     * refusal. */
    if (plan->conditional && plan->expect == DIMS_EXPECT_IMAGE) {
        plan->expect = DIMS_EXPECT_ANY;
    }

    for (i = 0; i < (int) parameter_count; i++) {
        free(parameters[i].value);
    }

    free(escaped_commands);
    free(command_string);
    free(image_url);
    free(signed_url);
    free(signature);
}

void
dims_plan_free(dims_plan *plan)
{
    free(plan->path);
    free(plan->commands);
    plan->path = NULL;
    plan->commands = NULL;
}
