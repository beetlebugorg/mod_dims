# Cache control

## DimsCacheExpire

```apacheconf
DimsCacheExpire 604800
```

How long a successful response may be cached, in seconds, when the origin says
nothing. Default 86400.

Sets `Cache-Control: max-age`, `Expires`, and `Edge-Control: downstream-ttl`.

## DimsNoImageCacheExpire

```apacheconf
DimsNoImageCacheExpire 60
```

How long an error image may be cached, in seconds. Default 60.

It is short on purpose. A long one caches a failure across a whole CDN.

## DimsErrorBackground

```apacheconf
DimsErrorBackground "#cccccc"
```

Draws the image a failed request answers with, in this colour, at the size the
commands asked for. A page that asked for 100 by 100 gets 100 by 100 whether
the request succeeded or not.

Any colour ImageMagick reads works, as a name or a hex value.

It takes precedence over `DimsDefaultImageURL`, and needs no fetch.

## DimsDefaultImageURL

```apacheconf
DimsDefaultImageURL https://images.example.com/missing.png
```

The image sent when a request fails, for clients whose own error image is
unset.

A single dash means none. Without an error image a failure returns its status
and no body, which is often what a caller would rather have.

A `file:///` URL is read from disk instead of fetched.

## Trusting the origin

The `trust`, `minSrc`, and `maxSrc` fields of
[`DimsAddClient`](/configuration/clients) decide whether the origin's own
`Cache-Control` is used, and the range it is clamped to. An origin asking for a
year is clamped to `maxSrc`, and one asking for a second is raised to `minSrc`.

## DimsOriginStatusMode

```apacheconf
DimsOriginStatusMode map
```

How a failure at the origin reaches the caller.

| Value | Effect |
|---|---|
| `forward` | report the status the origin returned. The default. |
| `map` | report 404 for a missing source, 504 for a timeout, and 502 for anything else |

`forward` tells a caller what the origin said, which also tells them whether a
host exists, whether it wants credentials, and whether a port is filtered.
`map` reports one of three answers and nothing else.
