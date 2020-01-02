package com.xebia.java_article;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class Utils {

    /**
     * Generate a key for AES (be aware: if you do not specify the key size it is up to the provider to select the
     * key size)
     */
    public static SecretKey generateKeyForAES() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate key");
        }
    }

    public static SecretKey generateKeyForChaCha20() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("ChaCha20");
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate key");
        }
    }

    public static SecretKey generateKeyForHMAC() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA512");
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate key");
        }
    }
}
