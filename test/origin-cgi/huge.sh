#!/bin/sh
# 64 MB, sent without a Content-Length so the limit has to be enforced while
# reading rather than from the declared size.
echo "Content-Type: image/png"
echo ""
dd if=/dev/zero bs=1048576 count=64 2>/dev/null
