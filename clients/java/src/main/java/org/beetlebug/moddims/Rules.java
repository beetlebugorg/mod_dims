package org.beetlebug.moddims;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * The signing rules both signers follow.
 *
 * <p>The module compiles these rules in C, and test/fixtures/signing.tsv holds
 * a case for each one.
 */
final class Rules {
    /** The parameters a /dims5/ signature never covers. */
    private static final Set<String> UNSIGNED =
            Set.of("sig", "url", "eurl", "_keys", "download");

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private Rules() {
    }

    /** An IllegalArgumentException whose message names the rule that fired. */
    static IllegalArgumentException bad(String kind, String detail) {
        return new IllegalArgumentException(kind + ": " + detail);
    }

    // -- Percent coding --

    /**
     * Percent encodes one query component: everything outside A-Za-z0-9-_.~
     * becomes %XX with uppercase hex, and a space becomes a plus.
     *
     * <p>URLEncoder escapes a tilde as %7E and leaves an asterisk alone, so it
     * produces a canonical query the module refuses.
     */
    static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length() * 3);

        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;

            if (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
                    || c >= '0' && c <= '9'
                    || c == '-' || c == '_' || c == '.' || c == '~') {
                out.append((char) c);
            } else if (c == ' ') {
                out.append('+');
            } else {
                out.append('%').append(HEX[c >> 4]).append(HEX[c & 0x0F]);
            }
        }

        return out.toString();
    }

    /**
     * Decodes a path or an image URL. A plus stays a plus, because the module
     * decodes both with ap_unescape_url.
     *
     * <p>A percent escape that is not two hex digits is an error, and so is
     * %00.
     *
     * <p>URLDecoder reads a plus as a space. The canonical query needs that,
     * and this decoder does not.
     */
    static String decodeStrict(String text) {
        byte[] in = text.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[in.length];
        int at = 0;

        for (int i = 0; i < in.length; i++) {
            if (in[i] != '%') {
                out[at++] = in[i];
                continue;
            }

            if (i + 2 >= in.length) {
                throw bad("bad-url", "a percent escape is cut short");
            }

            int high = hexValue(in[i + 1]);
            int low = hexValue(in[i + 2]);
            if (high < 0 || low < 0) {
                throw bad("bad-url", "a percent escape is not two hex digits");
            }
            if (high == 0 && low == 0) {
                throw bad("bad-url", "%00 in a signed field");
            }

            out[at++] = (byte) (high << 4 | low);
            i += 2;
        }

        return new String(out, 0, at, StandardCharsets.UTF_8);
    }

    /**
     * Decodes one query component the way the module does. A plus is a space,
     * and a percent escape that is not two hex digits passes through as it is.
     */
    static String decodeComponent(String text) {
        byte[] in = text.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[in.length];
        int at = 0;

        for (int i = 0; i < in.length; i++) {
            if (in[i] == '+') {
                out[at++] = ' ';
            } else if (in[i] == '%' && i + 2 < in.length
                    && hexValue(in[i + 1]) >= 0 && hexValue(in[i + 2]) >= 0) {
                out[at++] = (byte) (hexValue(in[i + 1]) << 4 | hexValue(in[i + 2]));
                i += 2;
            } else {
                out[at++] = in[i];
            }
        }

        return new String(out, 0, at, StandardCharsets.UTF_8);
    }

    private static int hexValue(byte b) {
        int c = b & 0xFF;

        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }

        return -1;
    }

    // -- Reading a URL --

    /** The path and the query of one URL. */
    record Parts(String path, int pathEnd, String query, boolean hasQuery) {
    }

    /** Where the path begins. An absolute URL has an authority before it. */
    static Parts split(String url) {
        int i = 0;
        while (i < url.length() && isSchemeByte(url.charAt(i))) {
            i++;
        }

        int start = 0;
        if (i > 0 && url.startsWith("://", i)) {
            start = i + 3;
            while (start < url.length()
                    && url.charAt(start) != '/' && url.charAt(start) != '?') {
                start++;
            }
        }

        String rest = url.substring(start);
        int question = rest.indexOf('?');

        if (question < 0) {
            return new Parts(rest, url.length(), "", false);
        }

        return new Parts(rest.substring(0, question), start + question,
                rest.substring(question + 1), true);
    }

    private static boolean isSchemeByte(char c) {
        return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
                || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.';
    }

    /** What follows the prefix in the path. */
    static String afterPrefix(String path, String prefix) {
        if (!path.startsWith(prefix)) {
            throw bad("bad-url", path + " does not start with " + prefix);
        }

        return path.substring(prefix.length());
    }

    /**
     * The last raw value of one query parameter, undecoded, or null.
     *
     * <p>The name is compared as it appears in the query. The module reads the
     * query the same way, so a percent escape in a name does not match here
     * either.
     */
    static String rawValue(String query, String name) {
        String found = null;

        for (String token : query.split("&", -1)) {
            if (token.startsWith(name + "=")) {
                found = token.substring(name.length() + 1);
            }
        }

        return found;
    }

    /** The image URL, decoded. The query must hold a url parameter. */
    static String imageUrl(String query) {
        String raw = rawValue(query, "url");

        if (raw == null) {
            throw bad("bad-url", "the query has no url");
        }

        return decodeStrict(raw);
    }

    // -- The canonical query --

    private record Param(String name, byte[] key, String value, int order) {
    }

    /**
     * Builds the third line of a /dims5/ message.
     *
     * <p>The order compares the bytes of the name. String.compareTo orders by
     * UTF-16 code unit, and the two disagree above U+FFFF.
     */
    static String canonicalQuery(String query) {
        List<Param> params = new ArrayList<>();

        for (String token : query.split("&", -1)) {
            if (token.isEmpty()) {
                continue;
            }

            int equals = token.indexOf('=');
            String name = equals < 0 ? token : token.substring(0, equals);
            // A parameter with no equals sign has an empty value.
            String value = equals < 0 ? "" : token.substring(equals + 1);

            name = decodeComponent(name);
            if (UNSIGNED.contains(name)) {
                continue;
            }

            params.add(new Param(name, name.getBytes(StandardCharsets.UTF_8),
                    decodeComponent(value), params.size()));
        }

        // A name that appears more than once keeps the order the query gives.
        params.sort(Comparator
                .comparing(Param::key, Rules::compareBytes)
                .thenComparingInt(Param::order));

        StringBuilder out = new StringBuilder();
        for (Param param : params) {
            if (out.length() > 0) {
                out.append('&');
            }
            out.append(escape(param.name())).append('=').append(escape(param.value()));
        }

        return out.toString();
    }

    private static int compareBytes(byte[] a, byte[] b) {
        int length = Math.min(a.length, b.length);

        for (int i = 0; i < length; i++) {
            int difference = (a[i] & 0xFF) - (b[i] & 0xFF);
            if (difference != 0) {
                return difference;
            }
        }

        return a.length - b.length;
    }

    /**
     * Whether a field is safe to put in a /dims5/ message. The message puts one
     * field per line, so a field holding a newline could stand in for two.
     */
    static boolean fieldOk(String field) {
        for (byte b : field.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if (c < 0x20 || c == 0x7F) {
                return false;
            }
        }

        return true;
    }

    /** The query with every sig parameter left out. */
    static String stripSig(String query) {
        StringBuilder out = new StringBuilder();

        for (String token : query.split("&", -1)) {
            if (token.isEmpty()) {
                continue;
            }

            int equals = token.indexOf('=');
            String name = equals < 0 ? token : token.substring(0, equals);

            if (!name.equals("sig")) {
                if (out.length() > 0) {
                    out.append('&');
                }
                out.append(token);
            }
        }

        return out.toString();
    }

    /**
     * Copies a signed URL with every url parameter replaced by one eurl.
     *
     * <p>The eurl goes where the last url was, so the output holds the
     * parameters in the order the input gave. Neither name is in the canonical
     * query, so the signature still matches.
     */
    static String swapUrlForEurl(String signedUrl, String eurl) {
        Parts parts = split(signedUrl);
        String[] tokens = parts.query().split("&", -1);

        int last = -1;
        for (int i = 0; i < tokens.length; i++) {
            if (tokens[i].startsWith("url=")) {
                last = i;
            }
        }

        StringBuilder out = new StringBuilder();
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];

            if (token.isEmpty()) {
                continue;
            }
            if (token.startsWith("url=") && i != last) {
                continue;
            }

            if (out.length() > 0) {
                out.append('&');
            }
            out.append(token.startsWith("url=") ? "eurl=" + eurl : token);
        }

        return signedUrl.substring(0, parts.pathEnd()) + "?" + out;
    }
}
