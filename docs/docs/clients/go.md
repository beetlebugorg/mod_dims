# Go

```
go get github.com/beetlebugorg/mod_dims/clients/moddims
```

Package `moddims` signs mod_dims URLs. It needs Go 1.24 and no dependency
outside the standard library.

## Sign a URL

```go
import "github.com/beetlebugorg/mod_dims/clients/moddims"

signer := moddims.Dims5{Key: os.Getenv("DIMS_SIGNING_KEY")}

signed, err := signer.Sign(
    "https://images.example.com/dims5/resize/100x100/?url=" +
        neturl.QueryEscape("http://origin:8080/grid.png"))
```

`Dims4` uses the client secret instead. Four segments follow the prefix: the
client id, the signature, the expiry, and the commands. Write a placeholder in
the signature segment. Its length sets the length of the signature, from 6
characters to 32.

```go
signer := moddims.Dims4{Secret: os.Getenv("DIMS_SECRET")}

signed, err := signer.Sign(
    "/dims4/CLIENT/xxxxxx/2147483647/resize/100x100/?url=" + encoded)
```

## The prefix

`Prefix` is what comes before the commands in the path. The zero value means
`Dims5Prefix` or `Dims4Prefix`. A caller behind a rewrite sets the public
prefix.

```go
signer := moddims.Dims5{Key: key, Prefix: "/img/"}
```

The commands are `resize/100x100/` either way, so the signature matches what
the module computes after the rewrite.

## Encrypt the image URL

`SignEncrypted` signs the URL and replaces `url` with the encrypted source.
The signature covers the plain image URL, so the server verifies the request
after it decrypts.

```go
signed, err := moddims.Dims5{Key: key}.SignEncrypted(rawURL)
signed, err := moddims.Dims4{Secret: secret}.SignEncrypted(rawURL, moddims.ECB)
```

`/dims5/` reads AES-128-GCM. `/dims4/` reads what
[`DimsEncryptionAlgorithm`](/configuration/clients) names, and its default is
AES-128-ECB.

`DeriveKey`, `Encrypt`, and `Decrypt` do the steps on their own.

## Errors

A returned error wraps a sentinel, so a caller tests it with `errors.Is`.

| Sentinel | Meaning |
|---|---|
| `ErrNoKey` | an empty `Key` or `Secret` |
| `ErrBadURL` | the signer cannot read the URL |
| `ErrBadField` | a control character in the commands or the image URL |
| `ErrBadEurl` | an eurl value the decoder cannot read |

## Releases

The module lives in a subdirectory, so its tag has that directory in front:

```
git tag clients/moddims/v1.0.0
git push origin clients/moddims/v1.0.0
```

The Go module proxy reads the tag. Pushing it is the whole release, and the
module version moves on its own tag.

## Tests

`go test ./...` reads `test/fixtures/signing.tsv` and runs every record as a
subtest, so a failure names the case. That file is what the C library and the
Java client read too.
