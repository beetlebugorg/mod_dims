package org.beetlebug.moddims;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Signs URLs for the /dims4/ endpoint. Immutable and safe to share. */
public final class Dims4Signer {
    /** The prefix the endpoint conventionally serves at. */
    public static final String DEFAULT_PREFIX = "/dims4/";

    /** How many characters of the digest the module compares. */
    private static final int SIGNATURE_LENGTH = 6;

    /** The whole hex MD5, the longest placeholder a caller writes. */
    private static final int DIGEST_LENGTH = 32;

    private final String secret;
    private final String prefix;

    /**
     * @param secret the client secret
     * @throws IllegalArgumentException when secret is null or empty
     */
    public Dims4Signer(String secret) {
        this(secret, DEFAULT_PREFIX);
    }

    public Dims4Signer(String secret, String prefix) {
        if (secret == null || secret.isEmpty()) {
            throw Rules.bad("bad-argument", "no secret");
        }

        this.secret = secret;
        this.prefix = (prefix == null || prefix.isEmpty()) ? DEFAULT_PREFIX : prefix;
    }

    /**
     * Returns url with a valid /dims4/ signature.
     *
     * <p>Four segments follow the prefix: the client id, the signature, the
     * expiry, and the commands. The caller writes a placeholder in the
     * signature segment, and its length sets the length of the signature,
     * from 6 characters to 32.
     *
     * <p>The image URL signs with every plus written as a space. The module
     * applies that rule on this endpoint, and Dims5Signer keeps the plus.
     *
     * @throws IllegalArgumentException when the path does not start with the
     *         prefix, a segment is missing, the expiry is not decimal digits,
     *         the placeholder is shorter than 6 characters, or the query has
     *         no url
     */
    public String sign(String url) {
        Path path = read(url);
        String digest = md5(message(path));

        // The path is rebuilt from its four segments, so a placeholder equal
        // to the client id or to the expiry still works.
        StringBuilder out = new StringBuilder();
        out.append(url, 0, path.clientStart);
        out.append(path.client).append('/');
        out.append(digest, 0, path.signature.length()).append('/');
        out.append(path.expires).append('/');
        out.append(path.rawCommands);

        if (path.hasQuery) {
            out.append('?').append(path.query);
        }

        return out.toString();
    }

    /**
     * Returns url with a valid signature and the image URL encrypted into
     * eurl. cipher names the scheme the server is configured for.
     *
     * <p>The value travels undecoded, because the module reads that parameter
     * as it appears in the query.
     */
    public String signEncrypted(String url, Eurl.Cipher cipher) {
        String signed = sign(url);
        Path path = read(url);

        // This endpoint reads one derivation whatever the secret looks like.
        byte[] key = Eurl.deriveKey("sha1:" + secret);

        return Rules.swapUrlForEurl(signed, Eurl.encrypt(path.imageUrl, key, cipher));
    }

    /** The four segments and the values the message needs. */
    private static final class Path {
        int clientStart;
        String client;
        String signature;
        String expires;
        String rawCommands;
        String commands;
        String imageUrl;
        java.util.List<String> values = new java.util.ArrayList<>();
        String query;
        boolean hasQuery;
    }

    private Path read(String url) {
        Rules.Parts parts = Rules.split(url);
        String rest = Rules.afterPrefix(parts.path(), prefix);

        String[] segments = rest.split("/", 4);
        if (segments.length < 4) {
            throw Rules.bad("bad-url",
                    "fewer than four segments after " + prefix);
        }

        Path path = new Path();
        path.clientStart = parts.pathEnd() - rest.length();
        path.client = segments[0];
        path.signature = segments[1];
        path.expires = segments[2];
        path.rawCommands = segments[3];
        path.query = parts.query();
        path.hasQuery = parts.hasQuery();

        // The module reads the expiry with atol, so any other text expires it.
        if (path.expires.isEmpty() || !path.expires.matches("[0-9]+")) {
            throw Rules.bad("bad-url", "the expiry is not decimal digits");
        }

        // The placeholder sets the length of the signature.
        if (path.signature.length() < SIGNATURE_LENGTH
                || path.signature.length() > DIGEST_LENGTH) {
            throw Rules.bad("bad-url", "the signature placeholder is "
                    + path.signature.length() + " characters");
        }

        // A space travels as %20 and signs as a plus.
        path.commands = Rules.decodeStrict(path.rawCommands).replace(' ', '+');

        // The module writes every plus in a /dims4/ image URL as a space after
        // it decodes the value.
        path.imageUrl = Rules.imageUrl(path.query).replace('+', ' ');

        // The values _keys names, in _keys order, as they appear in the query.
        String keys = Rules.rawValue(path.query, "_keys");
        if (keys != null) {
            for (String name : keys.split(",", -1)) {
                if (name.isEmpty()) {
                    continue;
                }

                String value = Rules.rawValue(path.query, name);
                // A name the query leaves out contributes nothing.
                path.values.add(value == null ? "" : value);
            }
        }

        return path;
    }

    /** The message this signer hashes. It holds the client secret. */
    private String message(Path path) {
        StringBuilder out = new StringBuilder();

        out.append(path.expires).append(secret);
        out.append(path.commands).append(path.imageUrl);
        for (String value : path.values) {
            out.append(value);
        }

        return out.toString();
    }

    /** The message for one URL, for FixtureTest. */
    String messageFor(String url) {
        return message(read(url));
    }

    private static String md5(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");

            StringBuilder out = new StringBuilder(32);
            for (byte b : digest.digest(message.getBytes(StandardCharsets.UTF_8))) {
                out.append(String.format("%02x", b));
            }

            return out.toString();
        } catch (NoSuchAlgorithmException e) {
            // MD5 is on every Java platform.
            throw new IllegalStateException(e);
        }
    }
}
