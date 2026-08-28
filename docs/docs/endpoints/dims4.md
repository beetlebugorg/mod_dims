# /dims4/

```
/dims4/<client>/<signature>/<expires>/<commands>/?url=<image>
```

A signed request. The signature covers the commands and the image URL, so
neither can be changed without the secret.

```
/dims4/CLIENT/6d3dcb/2147483647/resize/100x100/?url=https://example.com/cat.jpg
```

| Segment | Meaning |
|---|---|
| `client` | a client id from [`DimsAddClient`](/configuration/clients) |
| `signature` | the first six characters of the digest below |
| `expires` | when the URL stops working, in seconds since the epoch |
| `commands` | the [operations](/operations/) to run |

## Query parameters

| Name | Meaning |
|---|---|
| `url` | the source image |
| `eurl` | the source image, encrypted |
| `download` | `1` sends `Content-Disposition: attachment` |
| `optimizeResize` | overrides [`DimsOptimizeResize`](/configuration/output) |
| `overlay` | the watermark image, for the [watermark](/operations/special/watermark) command |
| `_keys` | which other parameters the signature covers, comma separated |

## The signature

An MD5 digest, hexadecimal, truncated to its first six characters. The message
is the expiry, the client's secret, the commands, and the image URL joined with
nothing between them.

[Signing](/signing) has the full construction, a worked example, and code.

A request whose `expires` has passed is refused, and so is one further ahead
than [`DimsSecretMaxExpiryPeriod`](/configuration/clients) allows.

:::warning
Six hexadecimal characters is 24 bits. One in 16.8 million random signatures
is accepted, and the signed path is the one that skips the host allowlist by
default. Set [`DimsAllowlistSigned`](/configuration/image-sources) to
`enforce` so the allowlist applies to a signed request too.
:::

## What the signature does not cover

`overlay` and `optimizeResize` are only covered when `_keys` lists them. A
caller who omits `_keys` can change either and keep a valid signature.
