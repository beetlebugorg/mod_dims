# Java

`org.beetlebug:moddims` publishes to GitHub Packages. That registry answers
`401` to an unauthenticated read, including from a public repository, so a
consumer authenticates to resolve the dependency.

Put a GitHub token with the `read:packages` scope in `~/.m2/settings.xml`:

```xml
<servers>
  <server>
    <id>github</id>
    <username>YOUR_GITHUB_USERNAME</username>
    <password>YOUR_GITHUB_TOKEN</password>
  </server>
</servers>
```

Then name the repository and the dependency:

```xml
<repositories>
  <repository>
    <id>github</id>
    <url>https://maven.pkg.github.com/beetlebugorg/mod_dims</url>
  </repository>
</repositories>

<dependency>
  <groupId>org.beetlebug</groupId>
  <artifactId>moddims</artifactId>
  <version>1.0.0</version>
</dependency>
```

Gradle reads the same credentials from a property or the environment:

```kotlin
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/beetlebugorg/mod_dims")
        credentials {
            username = System.getenv("GITHUB_ACTOR")
            password = System.getenv("GITHUB_TOKEN")
        }
    }
}

dependencies {
    implementation("org.beetlebug:moddims:1.0.0")
}
```

Java 17, and no runtime dependency.

## Sign a URL

```java
var signer = new Dims5Signer(System.getenv("DIMS_SIGNING_KEY"));

String signed = signer.sign(
    "https://images.example.com/dims5/resize/100x100/?url="
        + URLEncoder.encode("http://origin:8080/grid.png", UTF_8));
```

`Dims4Signer` uses the client secret instead. Four segments follow the prefix:
the client id, the signature, the expiry, and the commands. Write a
placeholder in the signature segment. Its length sets the length of the
signature, from 6 characters to 32.

```java
var signer = new Dims4Signer(System.getenv("DIMS_SECRET"));

String signed = signer.sign(
    "/dims4/CLIENT/xxxxxx/2147483647/resize/100x100/?url=" + encoded);
```

Both classes are immutable and safe to share between threads. `sign` creates a
new `Mac` on every call, because a `Mac` is not thread safe and is cheap to
create.

## The prefix

The second constructor argument is what comes before the commands in the path.
A caller behind a rewrite passes the public prefix.

```java
var signer = new Dims5Signer(key, "/img/");
```

The commands are `resize/100x100/` either way, so the signature matches what
the module computes after the rewrite.

## Encrypt the image URL

`signEncrypted` signs the URL and replaces `url` with the encrypted source.
The signature covers the plain image URL, so the server verifies the request
after it decrypts.

```java
String signed = new Dims5Signer(key).signEncrypted(rawUrl);
String legacy = new Dims4Signer(secret).signEncrypted(rawUrl, Eurl.Cipher.ECB);
```

`/dims5/` reads AES-128-GCM. `/dims4/` reads what
[`DimsEncryptionAlgorithm`](/configuration/clients) names, and its default is
AES-128-ECB.

`Eurl.deriveKey`, `Eurl.encrypt`, and `Eurl.decrypt` do the steps on their own.

## Errors

`IllegalArgumentException` is the whole error surface. A bad URL is a
programming error at the call site, and a checked exception would make every
caller write a handler for a case a correct caller never hits.

The message starts with the rule that fired: `bad-url`, `bad-field`,
`bad-argument`, or `bad-eurl`.

`HmacSHA256`, `MD5`, and `AES` are on every Java platform, so a
`NoSuchAlgorithmException` becomes an `IllegalStateException`.

## What the class writes itself

`URLEncoder` escapes a tilde as `%7E` and leaves an asterisk alone, so it
produces a canonical query the module refuses. `URLDecoder` reads a plus as a
space. The canonical query needs that, and `url` does not. The class writes
both.

`String.compareTo` orders by UTF-16 code unit, and the module orders by UTF-8
byte. The two disagree above U+FFFF, so the canonical query compares
`name.getBytes(UTF_8)`.

Java 17 has no HKDF, so `Eurl` does the extract and the expand from RFC 5869.

## Releases

The artifact moves on its own tag, with the directory in front:

```
git tag clients/java/v1.0.0
git push origin clients/java/v1.0.0
```

`release-java.yml` reads the version from the tag and deploys with the
built-in `GITHUB_TOKEN`. The release profile attaches the sources jar and the
javadoc jar.

## Tests

`mvn test` reads `test/fixtures/signing.tsv` and runs every record as its own
test, so a failure names the case. That file is what the C library and the Go
client read too.
