#!/bin/sh
# The fixture image without cache headers. httpd always adds a Last-Modified
# to a static file, so a target that does not send one has to be a script.
printf 'Content-Type: image/png\r\n\r\n'
cat /usr/local/apache2/htdocs/grid.png
