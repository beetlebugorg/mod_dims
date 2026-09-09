package org.beetlebug.moddims;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Signs URLs for the /dims5/ endpoint.
 *
 * <p>An instance holds the key and the prefix and nothing else. It is
 * immutable and safe to share between threads.
 */
public final class Dims5Signer {
    /** The prefix the endpoint conventionally serves at. */
    public static final String DEFAULT_PREFIX = "/dims5/";

    private final String key;
    private final String prefix;

    /**
     * @param key the DimsSigningKey
     * @throws IllegalArgumentException when key is null or empty
     */
    public Dims5Signer(String key) {
        this(key, DEFAULT_PREFIX);
    }

    /**
     * @param key    the DimsSigningKey
     * @param prefix what comes before the commands in the path. A caller
     *               behind a rewrite passes the public prefix.
     */
    public Dims5Signer(String key, String prefix) {
        if (key == null || key.isEmpty()) {
            throw Rules.bad("bad-argument", "no key");
        }

        this.key = key;
        this.prefix = (prefix == null || prefix.isEmpty()) ? DEFAULT_PREFIX : prefix;
    }

    /**
     * Returns url with a valid /dims5/ signature.
     *
     * <p>The signature covers everything between the prefix and the query.
     * sig goes on the end of the query, and an input that already holds one
     * gets a new one in its place.
     *
     * @param url the unsigned URL, absolute or a path
     * @throws IllegalArgumentException when the path does not start with the
     *         prefix, a percent escape is malformed, the query has no url, or
     *         the commands or the image URL hold a control character
     */
    public String sign(String url) {
        Rules.Parts parts = Rules.split(url);
        String commands = Rules.decodeStrict(Rules.afterPrefix(parts.path(), prefix));
        String imageUrl = Rules.imageUrl(parts.query());

        if (!Rules.fieldOk(commands) || !Rules.fieldOk(imageUrl)) {
            throw Rules.bad("bad-field", "a control character in a signed field");
        }

        String digest = hmac(message(commands, imageUrl, parts.query()));
        String query = Rules.stripSig(parts.query());

        return url.substring(0, parts.pathEnd()) + "?"
                + (query.isEmpty() ? "" : query + "&") + "sig=" + digest;
    }

    /**
     * Returns url with a valid signature and the image URL encrypted into
     * eurl. The signature covers the plain image URL, so the server verifies
     * the request after it decrypts.
     *
     * <p>The value is percent encoded, because the module decodes that
     * parameter.
     */
    public String signEncrypted(String url) {
        String signed = sign(url);
        String imageUrl = Rules.imageUrl(Rules.split(url).query());
        String eurl = Eurl.encrypt(imageUrl, Eurl.deriveKey(key), Eurl.Cipher.GCM);

        return Rules.swapUrlForEurl(signed, Rules.escape(eurl));
    }

    /** The message this signer hashes. FixtureTest asserts it. */
    static String message(String commands, String imageUrl, String query) {
        return commands + "\n" + imageUrl + "\n" + Rules.canonicalQuery(query);
    }

    /** The message for one URL, for FixtureTest. */
    static String messageFor(String url, String prefix) {
        Rules.Parts parts = Rules.split(url);
        String commands = Rules.decodeStrict(Rules.afterPrefix(parts.path(),
                (prefix == null || prefix.isEmpty()) ? DEFAULT_PREFIX : prefix));

        return message(commands, Rules.imageUrl(parts.query()), parts.query());
    }

    private String hmac(String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));

            StringBuilder out = new StringBuilder(64);
            for (byte b : mac.doFinal(message.getBytes(StandardCharsets.UTF_8))) {
                out.append(String.format("%02x", b));
            }

            return out.toString();
        } catch (NoSuchAlgorithmException | java.security.InvalidKeyException e) {
            // HmacSHA256 is on every Java platform.
            throw new IllegalStateException(e);
        }
    }
}
