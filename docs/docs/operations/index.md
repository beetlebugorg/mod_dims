# Operations

A command is a name, a slash, and its arguments. Several commands separated by
slashes run left to right.

```
resize/100x100/quality/70/format/webp
```

That resizes the image, sets JPEG quality to 70, then converts to WebP.

## Transformations

| Command | Arguments |
|---|---|
| [`resize`](/operations/transformations/resize) | a geometry |
| [`crop`](/operations/transformations/crop) | a geometry with an offset |
| [`thumbnail`](/operations/transformations/thumbnail) | a geometry |
| [`rotate`](/operations/transformations/rotate) | degrees |
| [`flipflop`](/operations/transformations/flipflop) | `horizontal` or `vertical` |
| [`legacy_thumbnail`, `legacy_crop`](/operations/transformations/legacy) | a geometry |

## Adjustments

| Command | Arguments |
|---|---|
| [`brightness`](/operations/adjustments/brightness) | brightness and contrast |
| [`sharpen`](/operations/adjustments/sharpen) | radius and sigma |
| [`grayscale`](/operations/adjustments/grayscale) | `true` |
| [`sepia`](/operations/adjustments/sepia) | a threshold from 0 to 1 |
| [`invert`](/operations/adjustments/invert) | `true` |
| [`autolevel`](/operations/adjustments/autolevel) | `true` |

## Output

| Command | Arguments |
|---|---|
| [`format`](/operations/output/format) | `jpg`, `png`, `gif`, `webp`, `tiff` |
| [`quality`](/operations/output/quality) | 1 to 100 |
| [`strip`](/operations/output/strip) | `true` or `false` |

## Special

| Command | Arguments |
|---|---|
| [`watermark`](/operations/special/watermark) | opacity, size, gravity |

## Geometry

Several commands take an ImageMagick geometry.

| Form | Effect |
|---|---|
| `100x100` | fit inside 100 by 100, keeping the aspect ratio |
| `100` | width 100, height follows |
| `x100` | height 100, width follows |
| `100x100!` | exactly 100 by 100, ignoring the aspect ratio |
| `100x100>` | only if the image is larger |
| `100x100<` | only if the image is smaller |
| `50%` | half the size |

A `+` in an offset sometimes arrives as a space, because some clients escape it
as `%20`. `crop` converts a space back to a `+`.

## Multi-frame sources

An animated GIF is returned unchanged by default, with every command skipped.
Set [`DimsAnimatedImages`](/configuration/output) to `transform` to run the
commands over every frame.
