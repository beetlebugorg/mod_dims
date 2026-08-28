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

## A minimal configuration

```apacheconf
LoadModule dims_module modules/libmod_dims.so

DimsAddClient development - 604800 604800 trust 300 86400 a-secret

<Location /dims4/>
    SetHandler dims4
</Location>
```

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
| `DimsStatusVerbose` | `On` |
| `DimsStripMetadata` | true |
| `DimsUserAgentEnabled` | false |
| `DimsUserAgentOverride` | none |
