# /dims-status/

```
/dims-status/
```

Reports that the server is alive, how long it has been up, and how many
requests have succeeded and failed.

```
ALIVE

Uptime:  2 days 3 hours 4 minutes
Restart time: Monday, 01-Jan-2026 00:00:00 UTC

mod_dims version: 4.0.0-beta (08881b4)
ImageMagick version: ImageMagick 7.1.2-30 Q8
libcurl version: libcurl/7.88.1 OpenSSL/3.0.20

Details
-------
Successful requests: 1024
Failed requests: 3

Download timeouts: 1
Imagemagick Timeouts: 0
```

The container's health check requests this endpoint.

:::note
The version lines name every library a caller would need to pick an exploit,
and the shipped configuration exposes this handler with no access control.
Restrict the location, or set
[`DimsStatusVerbose`](/configuration/output) to `Off`.
:::
