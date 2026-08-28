/*
 * Guarding an SVG source against an external reference.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "svgguard.h"

#include <apr_xml.h>
#include <strings.h>
#include <string.h>

/*
 * Reports whether the content is something ImageMagick reads as SVG. After an
 * optional byte order mark and leading whitespace, an SVG starts with an XML
 * declaration, a document type, a comment, or the svg element.
 */
static int
looks_like_svg(const char *data, apr_size_t len)
{
    apr_size_t i = 0;

    if (data == NULL || len == 0) {
        return 0;
    }

    if (len >= 3 && (unsigned char) data[0] == 0xEF &&
            (unsigned char) data[1] == 0xBB && (unsigned char) data[2] == 0xBF) {
        i = 3;
    }

    while (i < len && (data[i] == ' ' || data[i] == '\t' ||
            data[i] == '\r' || data[i] == '\n')) {
        i++;
    }

    if (i >= len || data[i] != '<') {
        return 0;
    }

    if (i + 1 < len && (data[i + 1] == '?' || data[i + 1] == '!')) {
        return 1;
    }

    return (i + 4 <= len && strncasecmp(data + i, "<svg", 4) == 0);
}

/*
 * Reports whether an href value points outside the document. An empty value, a
 * fragment, and a data URI stay inside it. Every other value is external.
 */
static int
href_is_external(const char *value)
{
    const char *v = value;

    if (v == NULL) {
        return 0;
    }

    while (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n') {
        v++;
    }

    if (*v == '\0' || *v == '#') {
        return 0;
    }

    return strncasecmp(v, "data:", 5) != 0;
}

/* Walks the element and its children for an external href. */
static int
elem_has_external_ref(const apr_xml_elem *elem)
{
    const apr_xml_attr *attr;
    const apr_xml_elem *child;

    for (attr = elem->attr; attr != NULL; attr = attr->next) {
        /* apr_xml holds the local name, so this matches href and xlink:href. */
        if (strcasecmp(attr->name, "href") == 0 &&
                href_is_external(attr->value)) {
            return 1;
        }
    }

    for (child = elem->first_child; child != NULL; child = child->next) {
        if (elem_has_external_ref(child)) {
            return 1;
        }
    }

    return 0;
}

int
dims_svg_is_safe(apr_pool_t *pool, const char *data, apr_size_t len,
                 const char **reason)
{
    apr_xml_parser *parser;
    apr_xml_doc *doc = NULL;
    apr_status_t rv;

    if (reason != NULL) {
        *reason = NULL;
    }

    if (!looks_like_svg(data, len)) {
        return 1;
    }

    parser = apr_xml_parser_create(pool);
    if (parser == NULL) {
        if (reason != NULL) {
            *reason = "the XML parser could not start";
        }
        return 0;
    }

    rv = apr_xml_parser_feed(parser, data, len);
    if (rv == APR_SUCCESS) {
        rv = apr_xml_parser_done(parser, &doc);
    }

    /* Refuse an SVG that does not parse, rather than let the renderer read it. */
    if (rv != APR_SUCCESS) {
        if (reason != NULL) {
            *reason = "the SVG does not parse as XML";
        }
        return 0;
    }

    if (doc != NULL && doc->root != NULL && elem_has_external_ref(doc->root)) {
        if (reason != NULL) {
            *reason = "the SVG references an external resource";
        }
        return 0;
    }

    return 1;
}
