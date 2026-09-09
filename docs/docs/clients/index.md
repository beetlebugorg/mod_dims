# Clients

A client signs a URL before a browser requests it. The signing rules live in
one C library, and the module compiles the same source.

| Client | What it is |
|---|---|
| [C library](/clients/c) | `libmoddims_sign`, the signing rules and the `eurl` ciphers |
| [Go](/clients/go) | `github.com/beetlebugorg/mod_dims/clients/moddims` |
| [Java](/clients/java) | `org.beetlebug:moddims` |
| [dims-sign](/clients/dims-sign) | a command that signs a URL and checks one |

## One contract

`test/fixtures/signing.tsv` holds a signed URL, a canonical query, and a
message for each case. The C suite, the Go suite, and the Java suite each read
that file and compare their own output against every field.

An `eurl` record goes the other way: it holds a ciphertext and the plain image
URL it decrypts to. A ciphertext holds a fresh nonce, so the file cannot pin
one a client produces. Each suite round trips its own encrypt through its own
decrypt instead.

The request suite sends each signed URL in that file to a running module, then
reads the signature counters to confirm the module verified all of them. The
file records what the server accepts.

## Which endpoint

Pick the signer that matches the endpoint the server serves.
[`/dims5/`](/endpoints/dims5) signs with HMAC-SHA256 under one key.
[`/dims4/`](/endpoints/dims4) signs with MD5 under a client secret.

An operator picks the location with `SetHandler`, and a reverse proxy in front
can rewrite a public path onto it. The path alone does not identify the
endpoint. A client names the endpoint, and names the prefix when it differs
from the conventional one.
