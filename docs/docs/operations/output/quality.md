# quality

```
quality/<1 to 100>
```

Sets the compression quality. It applies to JPEG and WebP, and does nothing for
a lossless format.

```
quality/70
```

The value only ever lowers. A request for a higher quality than the source
already has is ignored, because raising it adds bytes without adding detail.

A value outside 1 to 100 is refused with `400`, and so is one that is not a
number. A leading zero is decimal, so `quality/070` means 70.
