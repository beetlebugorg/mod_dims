# mod_dims

**mod_dims** is an Apache httpd module that resizes, crops, and reformats
images on request.

```
/dims5/resize/100x100/?url=https://example.com/cat.jpg&sig=ecd30f9f...
```

That fetches `cat.jpg`, resizes it to fit 100 by 100, and returns it.

Nothing is cached. Every variant is produced when it is asked for, so a site
keeps one original and serves as many renditions as it needs.

📖 **[Documentation](https://beetlebugorg.github.io/mod_dims/)**

## Features

- Resize, crop, thumbnail, rotate, and flip
- Adjust brightness, sharpness, and colour
- Convert between JPEG, PNG, GIF, WebP, and TIFF
- Composite a watermark
- Strip metadata and set compression quality
- Sign a request so it cannot be altered
- Restrict which hosts an image may come from

## Why use it

**Image variants on demand.** Define a rendition in a template or in frontend
code. There is no build step, no batch job, and no second copy of every image.

**Signed URLs.** A `/dims5/` URL is signed with HMAC-SHA256, so a caller
cannot change the image, the transformation, or any parameter that shapes it.

## Getting started

```bash
docker run -p 8000:8000 -e DIMS_SECRET=a-secret \
  ghcr.io/beetlebugorg/mod_dims:latest
```

Built for `linux/amd64` and `linux/arm64`.

See [Installation](https://beetlebugorg.github.io/mod_dims/installation) for
building from source and configuring httpd.

## Building

The build is CMake. The tests are C.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

The suite runs in a container, against a fixture origin:

```bash
make -C test test
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
