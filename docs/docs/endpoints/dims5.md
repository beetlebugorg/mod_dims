# /dims5/

```
/dims5/<commands>/?url=<image>&sig=<signature>
```

The endpoint to use. Every query parameter takes part in the signature apart
from five, so a caller cannot change the overlay, the resize factor, or
anything else without the key.

```
/dims5/resize/100x100/?url=https://example.com/cat.jpg&sig=6d3dcb...
```

There is no client id. One [`DimsSigningKey`](/configuration/clients) covers
the endpoint.

## Query parameters

| Name | Signed | Meaning |
|---|---|---|
| `url` | no | the source image |
| `eurl` | no | the source image, encrypted |
| `sig` | no | the signature itself |
| `download` | no | `1` sends `Content-Disposition: attachment` |
| `_keys` | no | accepted and ignored |
| anything else | **yes** | passed to the command that reads it |

`overlay` is signed, so a watermark URL cannot be replayed against a different
overlay.

## Signing

The message is three fields, one per line:

1. the commands, as they appear after `/dims5/`
2. the image URL, exactly as it appears in `url`, not percent encoded
3. the canonical query

Take the HMAC-SHA256 of that under the signing key, hex encoded and lowercase.
The whole digest is compared, and the comparison reads every byte whatever the
answer.

### The canonical query

Every signed parameter written `name=value`, percent encoded, ordered by name.
That is what a standard query string encoder produces from the signed
parameters after sorting them.

A parameter with several values contributes each of them, in the order the URL
gives.

The name is part of the string, so moving a character from one parameter to
the next changes the signature. The values alone would not: `a=ab&b=c` reads
the same as `a=a&b=bc`.

### Example

| | |
|---|---|
| key | `0123456789abcdef0123456789abcdef` |
| commands | `watermark/0.2,0.5,se/` |
| image | `http://origin:8080/grid.png` |
| overlay | `http://origin:8080/overlay.png` |

The canonical query is:

```
overlay=http%3A%2F%2Forigin%3A8080%2Foverlay.png
```

The message is:

```
watermark/0.2,0.5,se/
http://origin:8080/grid.png
overlay=http%3A%2F%2Forigin%3A8080%2Foverlay.png
```

Its HMAC-SHA256 is
`ecd30f9f48391ac8eb423f314913575132d401c082f9eb510d958c305d5a094d`.

### Code

```python title="Python"
import hmac, hashlib, urllib.parse

EXCLUDED = {"sig", "url", "eurl", "_keys", "download"}

def sign(key, commands, image_url, params):
    pairs = [(k, v) for k, v in sorted(params.items()) if k not in EXCLUDED]
    query = urllib.parse.urlencode(pairs, quote_via=urllib.parse.quote_plus)
    message = "\n".join([commands, image_url, query])
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()
```

```php title="PHP"
function sign($key, $commands, $imageUrl, $params) {
    $excluded = ['sig', 'url', 'eurl', '_keys', 'download'];
    $signed = array_diff_key($params, array_flip($excluded));
    ksort($signed);
    $message = implode("\n", [$commands, $imageUrl, http_build_query($signed)]);
    return hash_hmac('sha256', $message, $key);
}
```

```javascript title="JavaScript"
import {createHash, createHmac} from 'crypto';

const EXCLUDED = new Set(['sig', 'url', 'eurl', '_keys', 'download']);

function sign(key, commands, imageUrl, params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (!EXCLUDED.has(k)) q.append(k, v);
  }
  q.sort();
  const message = [commands, imageUrl, q.toString()].join('\n');
  return createHmac('sha256', key).update(message).digest('hex');
}
```

```ruby title="Ruby"
require 'openssl'
require 'uri'

EXCLUDED = %w[sig url eurl _keys download]

def sign(key, commands, image_url, params)
  signed = params.reject { |k, _| EXCLUDED.include?(k) }.sort
  message = [commands, image_url, URI.encode_www_form(signed)].join("\n")
  OpenSSL::HMAC.hexdigest('SHA256', key, message)
end
```

## Control characters

The message puts one field per line, so a control character in the commands or
the image URL is refused with `400`. Without that a field holding a line break
could stand in for two.

## eurl

`eurl` hides the source from a public caller. The key comes from the signing
key through HKDF-SHA256, and the value is AES-128-GCM.

1. Derive a 16 byte key with HKDF-SHA256 over the signing key, with the salt
   `go-dims` and empty info.
2. Encrypt the URL with AES-128-GCM and a 12 byte random IV.
3. Concatenate the IV, the ciphertext, and the tag, in that order.
4. Base64 the result.

A signing key with a `sha1:` prefix derives the key the older way instead:
SHA-1 of the rest, hex encoded, the first 16 characters uppercased. That path
holds 64 bits of key material spread across 16 bytes, so prefer the default.

`eurl` takes no part in the signature. The decrypted URL is what the message
covers.

## The error image

[`DimsErrorBackground`](/configuration/cache-control) draws a solid image at
the size the commands asked for, rather than fetching one. A page that asked
for 100 by 100 gets 100 by 100 whether the request succeeded or not, so its
layout holds.

Without it, a failure answers with its status and no body.
