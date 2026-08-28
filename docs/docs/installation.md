---
sidebar_position: 2
---

# Installation

## The container

```bash
docker pull ghcr.io/beetlebugorg/mod_dims:latest
docker run -p 8000:8000 ghcr.io/beetlebugorg/mod_dims:latest
```

It starts with nothing set. Every setting has a default, and the host
allowlist starts empty, which matches no host.

Built for `linux/amd64` and `linux/arm64`.

### Serving an image

`/dims3/` needs an allowlist of the hosts an image may come from:

```bash
docker run -p 8000:8000 \
  -e DIMS_WHITELIST="images.example.com" \
  ghcr.io/beetlebugorg/mod_dims:latest
```

```
http://localhost:8000/dims3/development/resize/100x100/?url=https://images.example.com/cat.jpg
```

`/dims4/` needs a shared secret instead:

```bash
docker run -p 8000:8000 -e DIMS_SECRET=a-secret ghcr.io/beetlebugorg/mod_dims:latest
```

The environment variables the container reads are in
[the container README](https://github.com/beetlebugorg/mod_dims/blob/main/docker/README.md).

## Building from source

The build is CMake. It needs httpd and APR headers, libcurl, OpenSSL, and
ImageMagick 7.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
sudo cmake --install build
```

`cmake --install` writes the module to the directory `apxs` reports, and the
colour profiles to `share/mod_dims/profiles`. It does not edit a running
configuration.

ImageMagick has to be built at quantum depth 8. Every packaged build is Q16,
which doubles the memory each request uses and changes every output byte.
`docker/Dockerfile.builder` is the toolchain this project builds against.

## Configuring httpd

```apacheconf
LoadModule dims_module modules/libmod_dims.so

DimsAddClient development - 604800 604800 trust 300 86400 a-secret
DimsAddWhitelist images.example.com

<Location /dims4/>
    SetHandler dims4
</Location>

<Location /dims-status/>
    SetHandler dims-status
</Location>
```

Every directive is in [Configuration](/configuration/).
