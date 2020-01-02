package com.xebia.java_article;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import static com.xebia.java_article.Utils.generateKeyForChaCha20;

public class ChaCha20 {

    public static void main(String[] args) {
        SecretKey secretKey = generateKeyForChaCha20();

        byte[] encryptedMsg = encrypt(secretKey, "Java magazine article".getBytes());
        System.out.println("Encrypted message is: " + Base64.getEncoder().encodeToString(encryptedMsg));
        System.out.println("Decrypted message is: " + new String(decrypt(secretKey, encryptedMsg)));
    }

    public static byte[] encrypt(SecretKey secretKey, byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            //Initialization without a ChaCha20ParameterSpec will cause the cipher to generate its own 12-byte nonce
            //internally and set the counter value to 1. The counter bytes may be obtained by invoking the Cipher.getIV() method.
            //Concatenate the nonce and the encrypted message, this is optional as the nonce and the counter can be shared in advance
            return ByteUtils.concatenate(cipher.getIV(), cipher.doFinal(message));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            throw new CryptoException("Unable to encrypt message");
        }
    }

    public static byte[] decrypt(SecretKey secretKey, byte[] message) {
        try {
            //First split the nonce and cipher text
            byte[] nonce = Arrays.copyOfRange(message, 0, 12);
            byte[] ct = Arrays.copyOfRange(message, 12, message.length);

            Cipher cipher = Cipher.getInstance("ChaCha20/None/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new ChaCha20ParameterSpec(nonce, 1));
            return cipher.doFinal(ct);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Unable to decrypt message");
        }
    }
}
