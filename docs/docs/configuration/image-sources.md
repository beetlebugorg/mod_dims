# Image sources

## DimsAddWhitelist

```apacheconf
DimsAddWhitelist images.example.com
DimsAddWhitelist *.cdn.example.net a.example.org
```

The hosts an image may come from. Several hosts may go on one line, and the
directive may be repeated.

A leading `*.` matches a name below the domain. `*.cdn.example.net` matches
`a.cdn.example.net` and `a.b.cdn.example.net`, and not `cdn.example.net`.

An empty allowlist matches nothing.

The allowlist applies to `/dims3/`. A `/dims4/` request skips it unless
`DimsAllowlistSigned` says otherwise. The watermark overlay follows the same
rule as the source image.

## DimsAllowlistSigned

```apacheconf
DimsAllowlistSigned enforce
```

Whether the allowlist applies to a signed request and to a redirect.

| Value | Effect |
|---|---|
| `log` | record what enforcing would refuse, and allow it. The default. |
| `enforce` | refuse it |

A signed request has never consulted the allowlist, so `log` is the default and
an operator can fill the allowlist from the log before changing it.

## DimsAllowPrivateAddresses

```apacheconf
DimsAllowPrivateAddresses Off
```

Whether a fetch may reach a private address: `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, and IPv6 unique local. `On` is the default, because some
origins sit inside the same network.

Loopback, link local, multicast, unspecified, and the ranges reserved for
documentation and benchmarking are refused whatever this is set to. That
includes `169.254.169.254`, the instance metadata address on EC2 and ECS.

The check runs on the resolved address, once per connection, so a name that
resolves to a refused address is refused whatever it is called, and every
redirect hop is checked on its own. The chain is capped at three redirects, and
only `http` and `https` are followed.

## DimsMaxSourceBytes

```apacheconf
DimsMaxSourceBytes 33554432
```

The largest source image to accept, in bytes. A larger source is refused before
it is decoded, both from a declared `Content-Length` and while reading.

`0`, the default, means no limit.

## DimsDefaultImagePrefix

```apacheconf
DimsDefaultImagePrefix https://images.example.com/
```

Prepended to a source that is not a full URL, so a request can name a path
rather than an origin.

## DimsDisableEncodedFetch

```apacheconf
DimsDisableEncodedFetch 1
```

Set to `1` to fetch the source URL exactly as given, rather than percent
encoding it first. `0` is the default.

## DimsOverlayCacheMaxEntries

```apacheconf
DimsOverlayCacheMaxEntries 1024
```

How many watermark overlays to keep on disk. The oldest go first. `0` means no
limit.

## DimsOverlayCacheMaxAge

```apacheconf
DimsOverlayCacheMaxAge 86400
```

How long an overlay stays on disk, in seconds. `0` means it never expires.

An overlay must pass the allowlist, but an unsigned request can still add an
allowlisted entry. Both bounds exist for that reason. A cache hit is checked
against the allowlist again, so an entry one host wrote does not serve on a
host whose allowlist refuses it.

## DimsProfileDir

```apacheconf
DimsProfileDir /usr/local/share/mod_dims/profiles
```

Where the ICC colour profiles are. They convert a CMYK source that has no
profile of its own.

The directory holds `CGATS21_CRPC2.icc` and `sRGB.icc`. `cmake --install`
writes them. Without them the module logs a warning at startup and a
profile-less CMYK source is not converted.

## SVG sources

The module reads an SVG source. ImageMagick's SVG renderer reads a local file
named by an `<image>` `href`, so the module refuses an SVG that references an
external resource. A self-contained SVG renders. An SVG that names a file, a
URL, or a relative path in an `href` is refused, and so is one that does not
parse.

The image the module ships with ImageMagick disables the coders the service
does not need, such as `PS`, `PDF`, `EPS`, and `MSL`. They can read a file,
write a file, or run a command. The image coders and the SVG renderer stay
enabled.
