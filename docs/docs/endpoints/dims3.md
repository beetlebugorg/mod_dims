# /dims3/

```
/dims3/<client>/<commands>/?url=<image>
```

An unsigned request. Nothing stops a caller asking for any transformation of
any image, so the host allowlist is what decides which images are reachable.

```
/dims3/CLIENT/resize/100x100/?url=https://images.example.com/cat.jpg
```

| Segment | Meaning |
|---|---|
| `client` | a client id from [`DimsAddClient`](/configuration/clients) |
| `commands` | the [operations](/operations/) to run |

It reads the same query parameters as [`/dims4/`](/endpoints/dims4), apart from
the signature.

## The allowlist

[`DimsAddWhitelist`](/configuration/image-sources) lists the hosts an image may
come from. An empty allowlist matches nothing, so `/dims3/` serves nothing
until one is set.

```apacheconf
DimsAddWhitelist images.example.com
DimsAddWhitelist *.cdn.example.net
```

A leading `*.` matches a name below the domain. `*.cdn.example.net` matches
`a.cdn.example.net` and not `cdn.example.net`.

:::warning
An allowlist is not a signature. Anyone can ask for any transformation of any
allowlisted image, which is unbounded work against your origin. Prefer
[`/dims4/`](/endpoints/dims4).
:::
