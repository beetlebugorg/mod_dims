# strip

```
strip/true
strip/false
```

Removes metadata: EXIF, colour profiles, comments, and the rest.

`true` strips. `false` keeps. Anything else, or no `strip` command at all,
follows [`DimsStripMetadata`](/configuration/output), which defaults to
stripping.

Stripping is worth a few kilobytes on a photograph and removes the camera,
lens, and GPS position along with it.

:::note
Stripping removes the colour profile too. A response converted from CMYK is
sRGB, and a viewer assumes sRGB when nothing says otherwise, so the result is
right.
:::
