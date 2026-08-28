# resize

```
resize/<geometry>
```

Scales the image. The aspect ratio is kept unless the geometry says otherwise.

```
resize/100x100      fit inside 100 by 100
resize/100          width 100, height follows
resize/x100         height 100, width follows
resize/100x100!     exactly 100 by 100, distorting if it has to
resize/100x100>     only if the image is larger
resize/100x100<     only if the image is smaller
resize/50%          half the size
```

A JPEG source is resampled at 2x1x1 chroma subsampling.

[`DimsOptimizeResize`](/configuration/output) makes ImageMagick decode a large
JPEG at a smaller scale first, which is faster and slightly softer.
