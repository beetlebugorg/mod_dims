# Clients

## DimsAddClient

```apacheconf
DimsAddClient <id> <errorImage> <maxAge> <downstreamTtl> <trust> <minSrc> <maxSrc> <secret>
```

Defines a client. Every request has a client id in its path, and a request
whose id is not defined is refused with `500`.

```apacheconf
DimsAddClient development - 604800 604800 trust 300 86400 a-secret
```

| Field | Meaning |
|---|---|
| `id` | the id in the URL |
| `errorImage` | the image sent when a request fails |
| `maxAge` | `Cache-Control: max-age` on the response, in seconds |
| `downstreamTtl` | `Edge-Control: downstream-ttl` on the response, in seconds |
| `trust` | `trust` to use the origin's cache headers, anything else to ignore them |
| `minSrc` | the lowest `max-age` accepted from the origin, in seconds |
| `maxSrc` | the highest `max-age` accepted from the origin, in seconds |
| `secret` | the key `/dims4/` signatures are computed with |

A single dash means the field is unset. A client with no secret refuses every
`/dims4/` request.

Repeat the directive for each client.

## DimsSecretMaxExpiryPeriod

```apacheconf
DimsSecretMaxExpiryPeriod 604800
```

How far ahead a `/dims4/` expiry may be, in seconds. A request further ahead
than this is refused, which stops a caller minting URLs that never expire.

`0`, the default, allows any expiry.

## DimsEncryptionAlgorithm

```apacheconf
DimsEncryptionAlgorithm AES/GCM/NoPadding
```

How the `eurl` parameter is encrypted. `AES/ECB/PKCS5Padding` is the default.
`AES/GCM/NoPadding` is the other value, and it is the better one: ECB has no
integrity check and no initialisation vector.

The key is derived from the client's secret: SHA-1 of the secret, the first 16
hexadecimal characters, uppercased.
