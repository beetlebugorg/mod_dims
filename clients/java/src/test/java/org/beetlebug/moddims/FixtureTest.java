package org.beetlebug.moddims;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * The shared fixture file. The C library and the Go client read the same one,
 * so a client that differs from the module fails here.
 */
class FixtureTest {
    /** The path the POM sets, so a run from an IDE finds the file too. */
    private static Path fixtureFile() {
        String path = System.getProperty("moddims.fixtures");

        if (path == null || path.isEmpty()) {
            throw new IllegalStateException(
                    "moddims.fixtures names the shared fixture file");
        }

        return Path.of(path);
    }

    /** \n, \t, and \\ are the only escapes. */
    private static String unescape(String value) {
        StringBuilder out = new StringBuilder(value.length());

        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);

            if (c != '\\' || i + 1 == value.length()) {
                out.append(c);
                continue;
            }

            i++;
            switch (value.charAt(i)) {
                case 'n' -> out.append('\n');
                case 't' -> out.append('\t');
                default -> out.append(value.charAt(i));
            }
        }

        return out.toString();
    }

    /**
     * Reads every record. A blank line ends a record, and a line starting with
     * # is a comment. A run that cannot open the file fails.
     */
    private static List<Map<String, String>> read() throws IOException {
        List<Map<String, String>> records = new ArrayList<>();
        Map<String, String> current = new HashMap<>();

        for (String line : Files.readAllLines(fixtureFile(), StandardCharsets.UTF_8)) {
            if (line.isEmpty()) {
                if (!current.isEmpty()) {
                    records.add(current);
                    current = new HashMap<>();
                }
                continue;
            }

            if (line.startsWith("#")) {
                continue;
            }

            int tab = line.indexOf('\t');
            assertTrue(tab >= 0, "a line has no tab: " + line);

            current.put(line.substring(0, tab), unescape(line.substring(tab + 1)));
        }

        if (!current.isEmpty()) {
            records.add(current);
        }

        return records;
    }

    private static Eurl.Cipher cipherOf(Map<String, String> record) {
        return "ecb".equals(record.get("cipher")) ? Eurl.Cipher.ECB : Eurl.Cipher.GCM;
    }

    /** An error record names the rule that must fire. */
    private static void expectError(Map<String, String> record, Runnable call) {
        IllegalArgumentException thrown =
                assertThrows(IllegalArgumentException.class, call::run);

        assertTrue(thrown.getMessage().startsWith(record.get("error") + ":"),
                record.get("case") + ": want " + record.get("error")
                        + ", got " + thrown.getMessage());
    }

    private static void checkEurl(Map<String, String> record) {
        byte[] key = Eurl.deriveKey(record.get("key"));
        Eurl.Cipher cipher = cipherOf(record);
        String input = record.get("input");

        if (record.containsKey("error")) {
            expectError(record, () -> Eurl.decrypt(input, key, cipher));
            return;
        }

        String plain = record.get("plain");
        assertEquals(plain, Eurl.decrypt(input, key, cipher), record.get("case"));

        // A fresh nonce means the file cannot pin a ciphertext, so the suite
        // round trips its own encrypt through its own decrypt.
        String again = Eurl.encrypt(plain, key, cipher);
        assertEquals(plain, Eurl.decrypt(again, key, cipher),
                record.get("case") + " round trip");
    }

    private static void checkSigning(Map<String, String> record) {
        boolean isDims5 = "dims5".equals(record.get("endpoint"));
        String prefix = record.get("prefix");
        String key = record.get("key");
        String input = record.get("input");

        if (record.containsKey("error")) {
            expectError(record, () -> {
                if (isDims5) {
                    new Dims5Signer(key, prefix).sign(input);
                } else {
                    new Dims4Signer(key, prefix).sign(input);
                }
            });
            return;
        }

        String signed = isDims5
                ? new Dims5Signer(key, prefix).sign(input)
                : new Dims4Signer(key, prefix).sign(input);

        assertEquals(record.get("signed"), signed, record.get("case"));

        if (record.containsKey("message")) {
            String message = isDims5
                    ? Dims5Signer.messageFor(input, prefix)
                    : new Dims4Signer(key, prefix).messageFor(input);

            assertEquals(record.get("message"), message,
                    record.get("case") + " message");
        }
    }

    @TestFactory
    List<DynamicTest> fixtures() throws IOException {
        List<Map<String, String>> records = read();
        assertTrue(records.size() >= 30,
                "the fixture file holds " + records.size() + " records");

        List<DynamicTest> tests = new ArrayList<>();
        for (Map<String, String> record : records) {
            tests.add(DynamicTest.dynamicTest(record.get("case"), () -> {
                if ("eurl".equals(record.get("endpoint"))) {
                    checkEurl(record);
                } else {
                    checkSigning(record);
                }
            }));
        }

        return tests;
    }

    /** The canonical query sorts by UTF-8 byte, and the file holds the case. */
    @TestFactory
    List<DynamicTest> sortStaysByteWise() {
        return List.of(DynamicTest.dynamicTest("supplementary name", () -> {
            String utf16First = "𐀀";
            String utf8First = "Ａ";

            assertTrue(utf16First.compareTo(utf8First) < 0,
                    "String.compareTo puts U+10000 first");
            assertNotEquals(
                    Rules.canonicalQuery("%F0%90%80%80=1&%EF%BC%A1=2"),
                    "%F0%90%80%80=1&%EF%BC%A1=2",
                    "the canonical query must put U+FF21 first");
        }));
    }
}
