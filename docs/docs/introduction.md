---
sidebar_position: 1
slug: /
---

# mod_dims

`mod_dims` is an Apache httpd module that resizes, crops, and reformats images
on request.

```
/dims4/CLIENT/6d3dcb/2147483647/resize/100x100/?url=https://example.com/cat.jpg
```

That fetches `cat.jpg`, resizes it to fit 100 by 100, and returns it.

Nothing is cached. Every variant is produced when it is asked for, so a site
keeps one original and serves as many renditions as it needs.

## What it does

- Resize, crop, thumbnail, rotate, and flip
- Adjust brightness, sharpness, and colour
- Convert between JPEG, PNG, GIF, WebP, and TIFF
- Composite a watermark
- Strip metadata and set compression quality

## Why use it

**Image variants on demand.** Ask for a size in a template or in frontend
code. There is no build step, no batch job, and no second copy of every image.

**Signed URLs.** A request cannot be altered without the shared secret.

## Where to start

- [Installation](/installation) runs the container.
- [Endpoints](/endpoints/) describes each URL shape.
- [Signing](/signing) shows how to sign a request.
- [Operations](/operations/) describes each command.
- [Configuration](/configuration/) describes each directive.
