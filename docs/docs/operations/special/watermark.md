# watermark

```
watermark/<opacity>,<size>,<gravity>
```

Composites another image on top of this one. The overlay comes from the
`overlay` query parameter.

```
/dims4/CLIENT/sig/2147483647/watermark/0.2,0.5,se/?url=<image>&overlay=<overlay>&_keys=overlay
```

| Argument | Meaning |
|---|---|
| `opacity` | 0 to 1, where 1 is opaque |
| `size` | a fraction of the larger side of the source image |
| `gravity` | where to put it |

All three are required. A shorter list is refused with `400`.

## Gravity

| Value | Position |
|---|---|
| `nw` `n` `ne` | top left, top, top right |
| `w` `c` `e` | left, centre, right |
| `sw` `s` `se` | bottom left, bottom, bottom right |

## The overlay

The overlay is fetched over HTTP and cached on disk under a name derived from
its URL. [`DimsOverlayCacheMaxEntries` and
`DimsOverlayCacheMaxAge`](/configuration/image-sources) bound that cache.

:::warning
The signature covers `overlay` only when `_keys` lists it. Without that, anyone
holding a valid watermark URL can swap the overlay for an image of their
choosing. Always include `_keys=overlay`.
:::
