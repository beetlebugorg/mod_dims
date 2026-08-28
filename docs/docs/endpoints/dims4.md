# /dims4/

```
/dims4/<client>/<signature>/<expires>/<commands>/?url=<image>
```

A signed request. The signature covers the commands and the image URL, so
neither can be changed without the secret.

```
/dims4/CLIENT/0c0bf3/2147483647/resize/100x100/?url=https://example.com/cat.jpg
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

## Signing

Join these with nothing between them:

1. `expires`, in seconds since the epoch
2. the client's secret
3. the commands, with a trailing slash and no leading one
4. the image URL, exactly as it appears in `url`, not percent encoded
5. the value of each parameter listed in `_keys`, in that order

Take the MD5 of that, hexadecimal and lowercase, and use its first six
characters.

### Example

| | |
|---|---|
| client | `CLIENT` |
| secret | `a-secret` |
| expires | `2147483647` |
| commands | `resize/100x100` |
| image | `https://example.com/cat.jpg` |

The message is:

```
2147483647a-secretresize/100x100/https://example.com/cat.jpg
```

Its MD5 is `0c0bf324d2eba5f0a2cbdf9a84a18332`, so the signature is `0c0bf3`
and the URL is:

```
/dims4/CLIENT/0c0bf3/2147483647/resize/100x100/?url=https%3A%2F%2Fexample.com%2Fcat.jpg
```

The commands have a trailing slash in the message. The image URL is percent
encoded in the query string but not in the message.

### Code

```bash title="Shell"
expires=2147483647
secret=a-secret
commands=resize/100x100/
url=https://example.com/cat.jpg

printf '%s%s%s%s' "$expires" "$secret" "$commands" "$url" | md5sum | cut -c1-6
```

```python title="Python"
import hashlib

def sign(secret, expires, commands, url, keys=None, params=None):
    message = f"{expires}{secret}{commands.rstrip('/')}/{url}"
    for key in (keys or []):
        message += params[key]
    return hashlib.md5(message.encode()).hexdigest()[:6]
```

```php title="PHP"
function sign($secret, $expires, $commands, $url, $keys = [], $params = []) {
    $message = $expires . $secret . rtrim($commands, '/') . '/' . $url;
    foreach ($keys as $key) {
        $message .= $params[$key];
    }
    return substr(md5($message), 0, 6);
}
```

```javascript title="JavaScript"
import {createHash} from 'crypto';

function sign(secret, expires, commands, url, keys = [], params = {}) {
  let message = `${expires}${secret}${commands.replace(/\/$/, '')}/${url}`;
  for (const key of keys) {
    message += params[key];
  }
  return createHash('md5').update(message).digest('hex').slice(0, 6);
}
```

```ruby title="Ruby"
require 'digest'

def sign(secret, expires, commands, url, keys = [], params = {})
  message = "#{expires}#{secret}#{commands.chomp('/')}/#{url}"
  keys.each { |key| message += params[key] }
  Digest::MD5.hexdigest(message)[0, 6]
end
```

### Signing another parameter

Only `url` and the commands are covered by default. To cover `overlay` as
well, list it in `_keys` and append its value to the message:

```
/dims4/CLIENT/<sig>/2147483647/watermark/0.2,0.5,se/?url=<image>&overlay=<overlay>&_keys=overlay
```

```
message = expires + secret + "watermark/0.2,0.5,se/" + image + overlay
```

Several parameters are appended in the order `_keys` gives, not in the order
they appear in the query string.

## Expiry

A request whose `expires` has passed is refused with `400`.
[`DimsSecretMaxExpiryPeriod`](/configuration/clients) caps how far ahead an
expiry may be, which stops a caller minting a URL that never expires.

## Unsigned parameters

`overlay` and `optimizeResize` are only covered when `_keys` lists them. A
caller who omits `_keys` can change either and keep a valid signature.

:::warning
Six hexadecimal characters is 24 bits. One in 16.8 million random signatures
is accepted, so a caller sending requests at a moderate rate finds a working
signature for a URL of their choosing in hours.

Set [`DimsAllowlistSigned`](/configuration/image-sources) to `enforce` so the
host allowlist applies to a signed request too. That bounds what a forged
signature can reach.
:::
