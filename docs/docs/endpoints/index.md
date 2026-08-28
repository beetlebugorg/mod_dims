# Endpoints

Four handlers, each set on a location.

| Handler | URL | Checked by |
|---|---|---|
| [`dims5`](/endpoints/dims5) | `/dims5/<commands>/?url=&sig=` | a signature |
| [`dims4`](/endpoints/dims4) | `/dims4/<client>/<signature>/<expires>/<commands>/?url=` | a signature |
| [`dims3`](/endpoints/dims3) | `/dims3/<client>/<commands>/?url=` | the host allowlist |
| [`dims-status`](/endpoints/status) | `/dims-status/` | nothing |
| [`dims-local`](/endpoints/local) | a file on disk | nothing |

`/dims5/` is the one to use. Its signature covers the commands, the image URL,
and every query parameter apart from five, and it uses HMAC-SHA256.

## Commands

Every endpoint that transforms an image reads the same command list: a name,
a slash, its arguments, a slash, the next name.

```
resize/100x100/quality/70/format/webp
```

They run left to right. [Operations](/operations/) describes each one.

## The source image

The `url` parameter contains it. The `eurl` parameter contains an encrypted
form, so the origin is not visible in the request.

The source may also sit in the path, after the commands. httpd collapses the
double slash, so it arrives as `http:/example.com/cat.jpg` and the module puts
the slash back.

## Refusals

| Status | Meaning |
|---|---|
| 400 | the request does not parse, or the guard refused the source |
| 404 | the source returned 404 |
| 500 | the client id is unknown, or the host is not on the allowlist |

A server with an error image configured sends that image instead, with the
status the failure produced. See
[`DimsDefaultImageURL`](/configuration/image-sources).
