# dims-sign

A command that signs a URL, prints the message behind one, and compares the
signature a URL holds against the one the key produces.

```
dims-sign (--dims4 | --dims5) [--key-file FILE] [--prefix P] [--eurl]
          [--cipher gcm|ecb] [--message | --verify] URL
```

The endpoint is a flag. The path alone does not identify the endpoint.
`--prefix` defaults to the prefix that flag names.

## The key

The key comes from `--key-file`, or from `DIMS_SIGNING_KEY` in the environment
when the flag is absent. A `--key-file` of `-` reads standard input.

There is no `--key` flag. A key on the command line is visible to every user of
the machine through `ps`, and the shell records it in the history file.

## Sign

```
$ dims-sign --dims5 --key-file dims.key \
    'https://images.example.com/dims5/resize/100x100/?url=http%3A%2F%2Forigin%3A8080%2Fgrid.png'
https://images.example.com/dims5/resize/100x100/?url=http%3A%2F%2Forigin%3A8080%2Fgrid.png&sig=e9d70afb...
```

A `/dims4/` URL holds a placeholder in the signature segment. Its length sets
the length of the signature.

```
$ DIMS_SIGNING_KEY=a-secret dims-sign --dims4 \
    '/dims4/CLIENT/xxxxxx/2147483647/resize/100x100/?url=https%3A%2F%2Fexample.com%2Fcat.jpg'
/dims4/CLIENT/0c0bf3/2147483647/resize/100x100/?url=https%3A%2F%2Fexample.com%2Fcat.jpg
```

## Encrypt the image URL

`--eurl` signs the URL and then replaces `url` with the encrypted source. The
signature covers the plain image URL, so the server verifies the request after
it decrypts.

```
$ dims-sign --dims5 --key-file dims.key --eurl "$url"
/dims5/resize/100x100/?eurl=SbEm%2BgYau0i4Bj%2BP%2FLOgRUf9UG3eeq3DRDh%2F...&sig=e9d70afb...
```

`/dims5/` reads AES-128-GCM. `/dims4/` reads what
[`DimsEncryptionAlgorithm`](/configuration/clients) names, and its default is
AES-128-ECB. `--cipher` names the one to use, and it defaults to the endpoint
default.

Every call writes a fresh IV, so two runs on one URL produce two values.

## Read the message

The server logs a mismatch without the digests. This command runs on a machine
that already holds the key, so it prints the message the key produces.

```
$ dims-sign --dims5 --key-file dims.key --message "$url"
watermark/0.2,0.5,se/
http://origin:8080/grid.png
overlay=http%3A%2F%2Forigin%3A8080%2Foverlay.png
```

The three lines are the commands, the image URL, and the canonical query. Read
each one against [`/dims5/`](/endpoints/dims5) to find the line that differs.

`--message` needs `--dims5`. A `/dims4/` message holds the client secret.

## Check a signature

```
$ dims-sign --dims5 --key-file dims.key --verify "$url"
signature mismatch
  wanted e9d70afb0b29520bae7fa47fb3de2d4c62c85f40d89636f6b190ac8055838bff
  got    6d3dcb0a1f29520bae7fa47fb3de2d4c62c85f40d89636f6b190ac8055838bff
```

`--verify` accepts both endpoints. It prints digests.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | a signature, or a match |
| `1` | a mismatch |
| `2` | a usage error |
| `3` | a URL the command cannot read |

## Where it installs

`cmake --install` writes `dims-sign` under `bin`. `docker/Dockerfile` copies
only `libmod_dims.so` out of the build stage, so the server image has no
`dims-sign`.
