/*
 * Golden file comparison.
 *
 * Derived from ../go-dims/internal/commands/golden_test.go, which has the
 * notice below through govips.
 *
 * The MIT License
 *
 * Copyright (c) Simple Things LLC and contributors
 * Copyright (c) 2025 Jeremy Collins (modified for go-dims)
 * Copyright (c) 2026 Jeremy Collins (ported to C for mod_dims)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef DIMS_TEST_GOLDEN_H
#define DIMS_TEST_GOLDEN_H

#include <stddef.h>

/*
 * Compares bytes against the golden file for the running test.
 *
 * name is the golden file stem, normally "<fixture>.<TestName>". ext is the
 * file extension including the dot.
 *
 * Under --update-golden the bytes are written and the comparison is skipped.
 * Otherwise a missing golden file is a failure, never a silent pass. On a
 * mismatch the bytes are written next to the golden file with a .failed stem
 * and both paths appear in the message.
 */
void assert_golden(const char *name, const unsigned char *body, size_t body_len,
                   const char *ext);

/* The extension for a Content-Type, for example ".png". Returns ".bin" when
 * the type is not one the suite knows. */
const char *dims_extension_for(const char *content_type);

#endif
