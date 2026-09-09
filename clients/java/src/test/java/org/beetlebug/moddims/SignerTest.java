package org.beetlebug.moddims;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** What a fixture record cannot cover. */
class SignerTest {
    private static final String KEY = "0123456789abcdef0123456789abcdef";
    private static final String SECRET = "t3stk3y";
    private static final String IMAGE = "http%3A%2F%2Forigin%3A8080%2Fgrid.png";

    /** Every record has a key, so the empty one is checked here. */
    @Test
    void refusesAnEmptyKey() {
        assertThrows(IllegalArgumentException.class, () -> new Dims5Signer(""));
        assertThrows(IllegalArgumentException.class, () -> new Dims5Signer(null));
        assertThrows(IllegalArgumentException.class, () -> new Dims4Signer(""));
    }

    /**
     * URLEncoder escapes a tilde and leaves an asterisk alone, so the class
     * writes its own table.
     */
    @Test
    void escapeDiffersFromUrlEncoder() {
        assertEquals("~", Rules.escape("~"));
        assertEquals("%7E", URLEncoder.encode("~", StandardCharsets.UTF_8));

        assertEquals("%2A", Rules.escape("*"));
        assertEquals("*", URLEncoder.encode("*", StandardCharsets.UTF_8));

        assertEquals("a+b", Rules.escape("a b"));
        assertEquals("%2B", Rules.escape("+"));
        assertEquals("-_.~", Rules.escape("-_.~"));
    }

    /**
     * The strict decoder keeps a plus and refuses a malformed escape. The
     * query decoder reads a plus as a space and copies a malformed escape,
     * because the module does.
     */
    @Test
    void theTwoDecodersDiffer() {
        assertEquals("a+b", Rules.decodeStrict("a+b"));
        assertEquals("a b", Rules.decodeComponent("a+b"));

        assertEquals("%zz", Rules.decodeComponent("%zz"));
        assertThrows(IllegalArgumentException.class, () -> Rules.decodeStrict("%zz"));
        assertThrows(IllegalArgumentException.class, () -> Rules.decodeStrict("%00"));
    }

    /** The canonical query orders by UTF-8 byte. */
    @Test
    void canonicalQueryOrdersByByte() {
        assertEquals("%EF%BC%A1=2&%F0%90%80%80=1",
                Rules.canonicalQuery("%F0%90%80%80=1&%EF%BC%A1=2"));
    }

    /** A name with several values keeps the order the query gives. */
    @Test
    void canonicalQueryKeepsValueOrder() {
        assertEquals("tag=b&tag=a", Rules.canonicalQuery("tag=b&tag=a"));
    }

    /** A URL with no query has no url parameter. */
    @Test
    void refusesAUrlWithNoQuery() {
        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> new Dims5Signer(KEY).sign("/dims5/resize/100x100/"));

        assertTrue(thrown.getMessage().startsWith("bad-url:"), thrown.getMessage());
    }

    /** An absolute URL keeps its scheme and authority. */
    @Test
    void keepsTheAuthority() {
        String in = "https://images.example.com/dims5/resize/100x100/?url=" + IMAGE;

        assertEquals(in + "&sig=e9d70afb0b29520bae7fa47fb3de2d4c62c85f40d"
                + "89636f6b190ac8055838bff", new Dims5Signer(KEY).sign(in));
    }

    /** SHA-1 of t3stk3y is f4fd45f7..., uppercased and cut to sixteen. */
    @Test
    void derivesBothKeys() {
        assertEquals("F4FD45F7F87CA8D7",
                new String(Eurl.deriveKey("sha1:" + SECRET), StandardCharsets.US_ASCII));

        assertArrayEqualsMessage(Eurl.deriveKey(KEY), Eurl.deriveKey("hkdf:" + KEY));

        assertThrows(IllegalArgumentException.class, () -> Eurl.deriveKey(""));
    }

    private static void assertArrayEqualsMessage(byte[] a, byte[] b) {
        assertEquals(new String(a, StandardCharsets.ISO_8859_1),
                new String(b, StandardCharsets.ISO_8859_1),
                "the hkdf prefix names the default");
    }

    /** A fresh IV every call on GCM, and one value every call on ECB. */
    @Test
    void gcmIsFreshAndEcbIsNot() {
        byte[] key = Eurl.deriveKey(KEY);
        String url = "http://origin:8080/grid.png";

        assertNotEquals(Eurl.encrypt(url, key, Eurl.Cipher.GCM),
                Eurl.encrypt(url, key, Eurl.Cipher.GCM));

        assertEquals(Eurl.encrypt(url, key, Eurl.Cipher.ECB),
                Eurl.encrypt(url, key, Eurl.Cipher.ECB));
    }

    /** A value the decoder cannot read. */
    @Test
    void refusesABadEurl() {
        byte[] key = Eurl.deriveKey(KEY);

        for (String value : new String[] {"!!!!", "AAAA", ""}) {
            IllegalArgumentException thrown = assertThrows(
                    IllegalArgumentException.class,
                    () -> Eurl.decrypt(value, key, Eurl.Cipher.GCM));

            assertTrue(thrown.getMessage().startsWith("bad-eurl:"),
                    thrown.getMessage());
        }
    }

    /**
     * The signed URL holds eurl in place of url, and the signature is the one
     * the plain URL produces.
     */
    @Test
    void signEncryptedKeepsTheSignature() {
        String input = "/dims5/resize/100x100/?url=" + IMAGE;
        String plain = new Dims5Signer(KEY).sign(input);
        String encrypted = new Dims5Signer(KEY).signEncrypted(input);

        String digest = plain.substring(plain.indexOf("&sig="));
        assertTrue(encrypted.endsWith(digest),
                "the signature must cover the plain image URL: " + encrypted);

        assertTrue(encrypted.contains("eurl="), encrypted);
        assertFalse(encrypted.contains("?url=") || encrypted.contains("&url="),
                encrypted);
    }
}
