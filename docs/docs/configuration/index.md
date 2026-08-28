# Configuration

Every directive goes in the server configuration, outside a `<Location>`. A
virtual host may set its own, and a virtual host that sets none starts from the
defaults rather than inheriting from the main server.

| Page | Directives |
|---|---|
| [Clients](/configuration/clients) | who may ask, and for how long |
| [Image sources](/configuration/image-sources) | where an image may come from |
| [Cache control](/configuration/cache-control) | what the response says about caching |
| [Output](/configuration/output) | what the response contains |
| [Resources](/configuration/resources) | what a request may consume |

## A basic configuration

```apacheconf
LoadModule dims_module modules/libmod_dims.so

DimsSigningKey a-long-random-string

<Location /dims5/>
    SetHandler dims5
</Location>
```

## Hardening

The shipped `conf/mod_dims.conf.example` sets these. Each is safe to relax when
your deployment needs it.

- `DimsMaxSourceBytes` caps the source size, so one request cannot exhaust
  memory. A malicious SVG is bounded by this too.
- `DimsAllowPrivateAddresses off` refuses a fetch to an internal address. The
  cloud metadata address is refused whatever this holds.
- `DimsStatusVerbose off` drops the component versions from the status page, so
  it does not name the libraries a caller would target. Restrict the
  `/dims-status/` location to your monitoring host as well.

Two more are worth enabling as your deployment allows.

- `DimsAllowlistSigned enforce` holds a signed request to the allowlist. A
  signed request skips it by default. Enable it once the allowlist covers your
  origins.
- Prefer `/dims5/` for a new integration. It signs with HMAC-SHA256.

## Every directive

| Directive | Default |
|---|---|
| `DimsAddClient` | none |
| `DimsAddWhitelist` | empty |
| `DimsAllowPrivateAddresses` | `On` |
| `DimsAllowlistSigned` | `log` |
| `DimsAnimatedImages` | `passthrough` |
| `DimsCacheExpire` | 86400 |
| `DimsDefaultImagePrefix` | none |
| `DimsDefaultImageURL` | none |
| `DimsDefaultOutputFormat` | none |
| `DimsDisableEncodedFetch` | 0 |
| `DimsDownloadTimeout` | 3000 |
| `DimsEncryptionAlgorithm` | `AES/ECB/PKCS5Padding` |
| `DimsErrorBackground` | none |
| `DimsIgnoreDefaultOutputFormat` | none |
| `DimsImagemagickAreaSize` | 128 |
| `DimsImagemagickDiskSize` | 2048 |
| `DimsImagemagickMapSize` | 1024 |
| `DimsImagemagickMemorySize` | 512 |
| `DimsImagemagickTimeout` | 3000 |
| `DimsIncludeDisposition` | false |
| `DimsMaxSourceBytes` | 0 |
| `DimsNoImageCacheExpire` | 60 |
| `DimsOptimizeResize` | 0 |
| `DimsOriginStatusMode` | `forward` |
| `DimsOverlayCacheMaxAge` | 86400 |
| `DimsOverlayCacheMaxEntries` | 1024 |
| `DimsProfileDir` | `share/mod_dims/profiles` |
| `DimsSecretMaxExpiryPeriod` | 0 |
| `DimsSigningKey` | none |
| `DimsStatusVerbose` | `On` |
| `DimsStripMetadata` | true |
| `DimsUserAgentEnabled` | false |
| `DimsUserAgentOverride` | none |
