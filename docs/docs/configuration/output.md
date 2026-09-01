# Output

## DimsStripMetadata

```apacheconf
DimsStripMetadata false
```

Whether to remove EXIF, colour profiles, and comments when the request does not
say. Default `true`. It applies to the error image as well as a successful
response.

A [`strip`](/operations/output/strip) command overrides it.

## DimsDefaultOutputFormat

```apacheconf
DimsDefaultOutputFormat webp
```

Converts every response to this format when the request has no
[`format`](/operations/output/format) command.

## DimsIgnoreDefaultOutputFormat

```apacheconf
DimsIgnoreDefaultOutputFormat gif png
```

Source formats that `DimsDefaultOutputFormat` leaves alone. Use it for a format
that would lose something in conversion, such as an animated GIF.

## DimsIncludeDisposition

```apacheconf
DimsIncludeDisposition true
```

Whether to send `Content-Disposition: inline` with the source filename. Default
`false`.

The `download=1` query parameter sends `attachment` instead, whatever this is
set to. The filename comes from the source URL, and every byte outside
printable ASCII is dropped before it reaches the header.

## DimsOptimizeResize

```apacheconf
DimsOptimizeResize 1.25
```

Makes ImageMagick decode a large JPEG at a smaller scale before resizing. The
value multiplies the target size to decide the decode size, so 1.25 decodes at
125 percent of the target.

Faster, and slightly softer. `0`, the default, is off.

The `optimizeResize` query parameter overrides it per request. That parameter
is only covered by a `/dims4/` signature when `_keys` lists it.

## DimsAnimatedImages

```apacheconf
DimsAnimatedImages transform
```

How a source with more than one frame is handled.

| Value | Effect |
|---|---|
| `passthrough` | return it unchanged, skipping every command. The default. |
| `transform` | run the commands over every frame |

`transform` coalesces the frames first, which holds every frame in full rather
than as a difference against the one before it, and runs every command once per
frame. A 27 frame source is 27 times the work.

## DimsUserAgentEnabled

```apacheconf
DimsUserAgentEnabled true
```

Whether to send a `User-Agent` when fetching a source. Default `false`, which
sends none.

## DimsUserAgentOverride

```apacheconf
DimsUserAgentOverride my-image-proxy/1.0
```

The `User-Agent` to send instead of `mod_dims/<version>`. Needs
`DimsUserAgentEnabled true`.

## DimsStatusVerbose

```apacheconf
DimsStatusVerbose Off
```

Whether [`/dims-status/`](/endpoints/status) prints the mod_dims, ImageMagick,
and libcurl versions. Default `On`.

The counters and the uptime print either way.
