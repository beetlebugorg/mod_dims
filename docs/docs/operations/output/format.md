# format

```
format/<format>
```

Converts the image.

```
format/jpg
format/png
format/gif
format/webp
format/tiff
```

Whatever ImageMagick was built to write is accepted. The toolchain this project
ships builds JPEG, PNG, GIF, WebP, and TIFF.

[`DimsDefaultOutputFormat`](/configuration/output) converts every response when
the request does not ask for a format.
