# mod-dims Docker Container

# How to build this image

```
$ docker build -t mod-dims:latest -f Dockerfile ..
```

# How to use this image

## Set DIMS_SECRET to use /dims4/ based signed URLs

```shell
$ docker run -e DIMS_SECRET=mysecret mod-dims:latest
```

## Enable stronger /dims4/ signatures (HMAC + strict validation)

```shell
$ docker run \
  -e DIMS_SECRET=myverylongsharedsecret \
  -e DIMS_SIGNATURE_ALGORITHM=hmac-sha256 \
  -e DIMS_STRICT_VALIDATION=true \
  mod-dims:latest
```

## Set DIMS_WHITELIST to use /dims3/ based URLs

```shell
$ docker run -e DIMS_WHITELIST="images.pexels.com" mod-dims:latest
```

# Configuration

| Environment Variables | Description | Default |
|-----------------------|-------------|---------|
| `DIMS_CLIENT` | Name of client | development |
| `DIMS_SECRET` | Shared secret for /dims4/ signatures | "" |
| `DIMS_DOWNLOAD_TIMEOUT` | Max time allowed for downloading source images, in milliseconds. | 60000 |
| `DIMS_CONNECT_TIMEOUT` | Max time allowed to establish upstream connection, in milliseconds. | 1000 |
| `DIMS_IMAGEMAGICK_TIMEOUT` | Max time allowed for Imagemagick processing, in milliseconds. | 20000 |
| `DIMS_MAX_DOWNLOAD_BYTES` | Hard cap for downloaded source image size, in bytes. | 67108864 |
| `DIMS_MAX_REDIRECTS` | Max redirect hops for upstream fetches. | 5 |
| `DIMS_ALLOWED_FETCH_SCHEMES` | Comma-separated allowed upstream schemes. | `http,https` |
| `DIMS_LOG_SENSITIVE_DATA` | Enable sensitive URL/signature logs (`true`/`false`). | `false` |
| `DIMS_ENCRYPTION_ALGORITHM` | `eurl` algorithm (`AES/GCM/NoPadding` or `AES/ECB/PKCS5Padding`). | `AES/GCM/NoPadding` |
| `DIMS_ALLOW_LEGACY_ECB` | Allow legacy ECB encrypted URLs (`true`/`false`). | `false` |
| `DIMS_NO_IMAGE_URL` | URL (http(s):// or file:///) to an image displayed for errors | "http://placehold.it/350x150" |
| `DIMS_CACHE_CONTROL_MAX_AGE` | Cache control max age header setting, in seconds | 604800 |
| `DIMS_EDGE_CONTROL_DOWNSTREAM_TTL` | Edge control downstream TTL | 604800 |
| `DIMS_TRUST_SOURCE` | Whether or not to trust origin cache headers | true |
| `DIMS_MIN_SOURCE_CACHE` | Min max-age to accept from image origin, in seconds | 604800 |
| `DIMS_MAX_SOURCE_CACHE` | Max max-age to accept from image origin, in seconds | 604800 |
| `DIMS_CACHE_EXPIRE` | Default expire time when no cache headers are present on origin image, in seconds | 604800 |
| `DIMS_NO_IMAGE_CACHE_EXPIRE` | Time to cache "no image" (i.e. dims failures), in seconds | 60 |
| `DIMS_SIGNATURE_ALGORITHM` | Signature mode for `/dims4/` (`legacy-md5` or `hmac-sha256`) | `legacy-md5` |
| `DIMS_STRICT_VALIDATION` | Enable stricter signature/query validation rules (`true`/`false`) | `false` |
