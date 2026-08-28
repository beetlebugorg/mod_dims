#!/bin/sh
# An origin that answers far later than any download timeout. The cases that
# assert a timeout status point here.
sleep 5
printf 'Content-Type: image/png\r\n\r\n'
