package org.beetlebug.moddims;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The eurl parameter: an image URL encrypted under a key derived from the
 * secret.
 *
 * <p>The signature covers the plain image URL, so the server verifies the
 * request after it decrypts.
 */
public final class Eurl {
    /** Which cipher an eurl value uses. */
    public enum Cipher {
        /**
         * AES-128-GCM. /dims5/ reads it, and /dims4/ reads it under
         * DimsEncryptionAlgorithm AES/GCM/NoPadding.
         */
        GCM,

        /**
         * AES-128-ECB with PKCS5 padding, the /dims4/ default. It has no
         * integrity check and no IV.
         */
        ECB
    }

    /** The AES key both schemes use. */
    private static final int KEY_BYTES = 16;

    /** What a GCM value has before and after the ciphertext. */
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    /** The salt the key derivation uses. Changing it invalidates every eurl. */
    private static final byte[] SALT = "go-dims".getBytes(StandardCharsets.UTF_8);

    private static final SecureRandom RANDOM = new SecureRandom();

    private Eurl() {
    }

    /**
     * Returns the AES key an eurl value uses.
     *
     * <p>A secret with a sha1: prefix uses the older path: SHA-1 of the rest,
     * hex encoded, the first 16 characters uppercased. Anything else uses
     * HKDF-SHA256, with a hkdf: prefix stripped first.
     *
     * <p>/dims4/ reads the older path whatever the secret looks like, so a
     * /dims4/ caller writes sha1: in front of the client secret.
     *
     * @throws IllegalArgumentException when secret is null or empty
     */
    public static byte[] deriveKey(String secret) {
        if (secret == null || secret.isEmpty()) {
            throw Rules.bad("bad-argument", "no secret");
        }

        if (secret.startsWith("sha1:")) {
            return sha1Key(secret.substring(5));
        }

        String material = secret.startsWith("hkdf:") ? secret.substring(5) : secret;

        return hkdf(material.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Returns the eurl value for one image URL.
     *
     * <p>A GCM value is the 12 byte IV, the ciphertext, and the 16 byte tag,
     * base64 encoded. The IV comes from SecureRandom, so two calls on one URL
     * under one key produce two values. An ECB value is the ciphertext alone.
     */
    public static String encrypt(String imageUrl, byte[] key, Cipher cipher) {
        try {
            SecretKeySpec spec = new SecretKeySpec(key, "AES");
            byte[] plain = imageUrl.getBytes(StandardCharsets.UTF_8);

            if (cipher == Cipher.ECB) {
                javax.crypto.Cipher ecb =
                        javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
                ecb.init(javax.crypto.Cipher.ENCRYPT_MODE, spec);

                return Base64.getEncoder().encodeToString(ecb.doFinal(plain));
            }

            byte[] iv = new byte[IV_BYTES];
            RANDOM.nextBytes(iv);

            javax.crypto.Cipher gcm =
                    javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(javax.crypto.Cipher.ENCRYPT_MODE, spec,
                    new GCMParameterSpec(TAG_BITS, iv));

            byte[] sealed = gcm.doFinal(plain);
            byte[] out = new byte[iv.length + sealed.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(sealed, 0, out, iv.length, sealed.length);

            return Base64.getEncoder().encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns the image URL one eurl value holds, so a caller reads back what
     * it wrote.
     *
     * @throws IllegalArgumentException when the value is not base64, is too
     *         short for its scheme, or fails its tag check
     */
    public static String decrypt(String eurl, byte[] key, Cipher cipher) {
        byte[] bytes;

        try {
            bytes = Base64.getDecoder().decode(eurl);
        } catch (IllegalArgumentException e) {
            throw Rules.bad("bad-eurl", "the value is not base64");
        }

        try {
            SecretKeySpec spec = new SecretKeySpec(key, "AES");

            if (cipher == Cipher.ECB) {
                if (bytes.length < KEY_BYTES || bytes.length % KEY_BYTES != 0) {
                    throw Rules.bad("bad-eurl", "the value is not whole blocks");
                }

                javax.crypto.Cipher ecb =
                        javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
                ecb.init(javax.crypto.Cipher.DECRYPT_MODE, spec);

                return new String(ecb.doFinal(bytes), StandardCharsets.UTF_8);
            }

            if (bytes.length <= IV_BYTES + TAG_BITS / 8) {
                throw Rules.bad("bad-eurl",
                        "the value cannot hold an IV, a ciphertext, and a tag");
            }

            javax.crypto.Cipher gcm =
                    javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(javax.crypto.Cipher.DECRYPT_MODE, spec,
                    new GCMParameterSpec(TAG_BITS, bytes, 0, IV_BYTES));

            // The tag check happens here. A value someone edited fails.
            byte[] plain = gcm.doFinal(bytes, IV_BYTES, bytes.length - IV_BYTES);

            return new String(plain, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw Rules.bad("bad-eurl", "the value does not decrypt");
        }
    }

    /** SHA-1 of the secret, hex, the first 16 characters uppercased. */
    private static byte[] sha1Key(String secret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] sum = digest.digest(secret.getBytes(StandardCharsets.UTF_8));

            StringBuilder hex = new StringBuilder(40);
            for (byte b : sum) {
                hex.append(String.format("%02X", b));
            }

            return hex.substring(0, KEY_BYTES).getBytes(StandardCharsets.US_ASCII);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * HKDF-SHA256 with an empty info, for 16 bytes. Java 17 has no HKDF, so
     * this is the extract and the first expand block from RFC 5869.
     */
    private static byte[] hkdf(byte[] secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");

            mac.init(new SecretKeySpec(SALT, "HmacSHA256"));
            byte[] pseudoRandom = mac.doFinal(secret);

            mac.init(new SecretKeySpec(pseudoRandom, "HmacSHA256"));
            byte[] block = mac.doFinal(new byte[] {1});

            byte[] key = new byte[KEY_BYTES];
            System.arraycopy(block, 0, key, 0, KEY_BYTES);

            return key;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
