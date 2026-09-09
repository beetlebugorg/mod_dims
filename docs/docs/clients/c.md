# C library

`libmoddims_sign` holds the `/dims4/` and `/dims5/` signing rules. The module
compiles the same source.

It needs C99 and libcrypto. It does not need APR and it does not need httpd.

## Build

The library installs with the module.

```
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
cmake --install build
```

That writes `dims_sign.h` under `include/dims`, `libmoddims_sign.a` and the
shared library under `lib`, `dims-sign` under `bin`, and `dims-sign.pc` under
`lib/pkgconfig`.

`pkg-config` resolves `-lmoddims_sign` to the shared library. Pass
`--static` to link the archive.

```
cc app.c $(pkg-config --cflags --libs dims-sign)
```

## Sign a URL

```c
#include <dims_sign.h>
#include <stdio.h>
#include <stdlib.h>

int
main(void)
{
    const char *url =
        "https://images.example.com/dims5/resize/100x100/"
        "?url=http%3A%2F%2Forigin%3A8080%2Fgrid.png";
    char *signed_url;
    dims_sign_status status;

    status = dims_sign_dims5_url(url, getenv("DIMS_SIGNING_KEY"), NULL,
                                 &signed_url);
    if (status != DIMS_SIGN_OK) {
        fprintf(stderr, "cannot sign: %s\n", dims_sign_strerror(status));
        return 1;
    }

    puts(signed_url);
    dims_sign_free(signed_url);

    return 0;
}
```

`dims_sign_dims4_url` uses the client secret instead of the signing key. Four
segments follow the prefix: the client id, the signature, the expiry, and the
commands. Write a placeholder in the signature segment. Its length sets the
length of the signature, from 6 characters to 32.

## The prefix

The third argument is what comes before the commands in the path. `NULL` means
`/dims5/` or `/dims4/`. A caller behind a rewrite passes the public prefix.

```c
dims_sign_dims5_url("https://cdn.example.com/img/resize/100x100/?url=...",
                    key, "/img/", &signed_url);
```

The commands are `resize/100x100/` either way, so the signature matches what
the module computes after the rewrite.

## Memory

A string of unknown length comes back allocated. Release it with
`dims_sign_free`. A digest of fixed length goes into a caller buffer, because
its size is a compile time constant.

A call that fails leaves the out parameter untouched and does not allocate.

## Thread safety

Every function is safe to call from any thread. No function reads or writes
static state.

## Encrypting the image URL

`eurl` hides the source from a public caller. The signature covers the plain
image URL, so the server verifies the request after it decrypts.

```c
char *signed_url;

dims_sign_dims5_eurl_url(url, key, NULL, &signed_url);
```

That signs the URL and replaces `url` with `eurl` in one call. The `/dims4/`
form takes the cipher the server is configured for:

```c
dims_sign_dims4_eurl_url(url, secret, NULL, DIMS_SIGN_EURL_ECB, &signed_url);
```

| Endpoint | Key | Cipher |
|---|---|---|
| `/dims5/` | HKDF-SHA256 of the signing key, salt `go-dims` | AES-128-GCM |
| `/dims4/` | SHA-1 of the client secret, hex, first 16 characters uppercased | AES-128-ECB, or GCM under [`DimsEncryptionAlgorithm`](/configuration/clients) |

`dims_sign_derive_key` and `dims_sign_eurl_encrypt` do the two steps on their
own. `dims_sign_eurl_decrypt` reads a value back, so a caller can check what it
wrote.

A GCM value is the 12 byte IV, the ciphertext, and the 16 byte tag, base64
encoded. The IV comes from the system random source, so two calls on one URL
produce two values.

## Status codes

| Status | Meaning |
|---|---|
| `DIMS_SIGN_OK` | the call produced a result |
| `DIMS_SIGN_MEMORY` | malloc refused |
| `DIMS_SIGN_BAD_ARGUMENT` | a required argument is NULL or empty |
| `DIMS_SIGN_BAD_URL` | the signer cannot read the URL |
| `DIMS_SIGN_BAD_FIELD` | a signed field holds a control character |
| `DIMS_SIGN_CRYPTO` | libcrypto refused |
| `DIMS_SIGN_BAD_EURL` | an eurl value is not base64, is too short, or fails its tag check |

`dims_sign_strerror` returns a short description of each one.

## What the signer does not do

It does not repair the URL. The caller supplies a valid one. A percent escape
that is not two hex digits gives `DIMS_SIGN_BAD_URL`.

It does not read an image URL out of the path. `/dims4/` also accepts the
image URL as the last path segment. The `url` query parameter is the
documented form, and the signer covers only that form.
