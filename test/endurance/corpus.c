/*
 * Reading the corpus manifest.
 *
 * The manifest is what test/endurance/corpus.sh wrote. Each line names a file
 * on the origin, the format the toolchain read it as, its size, and what a
 * request for it must do.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "soak.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *
dims_class_name(dims_source_class klass)
{
    switch (klass) {
        case DIMS_CLASS_IMAGE:  return "image";
        case DIMS_CLASS_REJECT: return "reject";
        default:                return "either";
    }
}

static int
push(size_t **list, size_t *count, size_t *capacity, size_t value)
{
    if (*count == *capacity) {
        size_t next = (*capacity == 0) ? 64 : *capacity * 2;
        size_t *grown = realloc(*list, next * sizeof(**list));

        if (grown == NULL) {
            return 0;
        }

        *list = grown;
        *capacity = next;
    }

    (*list)[(*count)++] = value;

    return 1;
}

int
dims_corpus_load(dims_corpus *corpus, const char *path)
{
    FILE *file = fopen(path, "r");
    char line[2048];
    size_t capacity = 0;
    size_t image_capacity = 0;
    size_t reject_capacity = 0;
    size_t either_capacity = 0;

    memset(corpus, 0, sizeof(*corpus));

    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *name;
        char *format;
        char *bytes;
        char *klass;
        char *state = NULL;
        dims_source *item;
        size_t index;

        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        line[strcspn(line, "\r\n")] = '\0';

        name = strtok_r(line, "\t", &state);
        format = strtok_r(NULL, "\t", &state);
        bytes = strtok_r(NULL, "\t", &state);
        klass = strtok_r(NULL, "\t", &state);

        if (name == NULL || format == NULL || bytes == NULL || klass == NULL) {
            continue;
        }

        if (corpus->count == capacity) {
            size_t next = (capacity == 0) ? 1024 : capacity * 2;
            dims_source *grown = realloc(corpus->items, next * sizeof(*grown));

            if (grown == NULL) {
                fclose(file);
                dims_corpus_free(corpus);
                return 0;
            }

            corpus->items = grown;
            capacity = next;
        }

        index = corpus->count;
        item = &corpus->items[index];
        item->name = strdup(name);
        item->format = strdup(format);
        item->bytes = strtol(bytes, NULL, 10);

        if (strcmp(klass, "image") == 0) {
            item->klass = DIMS_CLASS_IMAGE;
            push(&corpus->image, &corpus->image_count, &image_capacity, index);
        } else if (strcmp(klass, "reject") == 0) {
            item->klass = DIMS_CLASS_REJECT;
            push(&corpus->reject, &corpus->reject_count, &reject_capacity, index);
        } else {
            item->klass = DIMS_CLASS_EITHER;
            push(&corpus->either, &corpus->either_count, &either_capacity, index);
        }

        corpus->count++;
    }

    fclose(file);

    return corpus->count > 0;
}

void
dims_corpus_free(dims_corpus *corpus)
{
    size_t i;

    for (i = 0; i < corpus->count; i++) {
        free(corpus->items[i].name);
        free(corpus->items[i].format);
    }

    free(corpus->items);
    free(corpus->image);
    free(corpus->reject);
    free(corpus->either);
    memset(corpus, 0, sizeof(*corpus));
}
