package com.xebia.java_article;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Utils {

    public static byte[] generateIV(int length) {
        byte[] ivBytes = new byte[length];
        new SecureRandom().nextBytes(ivBytes);
        return ivBytes;
    }

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

    /**
     * Generate a key for HMAC: note that the key should be at least as long as the hashing output function
     */
    public static SecretKey generateKeyForHMAC() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA512");
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate key");
        }
    }

    public static KeyPair generateRsaKeyPair() {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate key");
        }
    }
}
