package com.xebia.java_article;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import static com.xebia.java_article.Utils.generateIV;
import static com.xebia.java_article.Utils.generateKeyForAES;

public class AES_CBC {

    public static void main(String[] args) {
        //Generate a 256 bits key, the key defines the strength of the AES encryption, possible values: AES-128/AES-192 and AES-256
        SecretKey secretKey = generateKeyForAES();

        byte[] encryptedMsg = encrypt(secretKey, "Java magazine article".getBytes());
        System.out.println("Encrypted message is: " + Base64.getEncoder().encodeToString(encryptedMsg));
        System.out.println("Decrypted message is: " + new String(decrypt(secretKey, encryptedMsg)));
    }

    public static byte[] encrypt(SecretKey secretKey, byte[] message) {
        try {
            //Generate the IV yourself, as Cipher.getIV() might return a non random one it all depends on the underlying security provider
            byte[] iv = generateIV();

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

            //Concatenate the IV and the encrypted message (IV MUST BE random)
            return ByteUtils.concatenate(iv, cipher.doFinal(message));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            // Never ever leak details about what went wrong during the encryption / decryption otherwise you might be
            // vulnerable to a padding oracle attack, timing attack etc.
            throw new CryptoException("Unable to encrypt message");
        }
    }

    public static byte[] decrypt(SecretKey secretKey, byte[] message) {
        try {
            //First split the IV and cipher text
            byte[] iv = Arrays.copyOfRange(message, 0, 16);
            byte[] ct = Arrays.copyOfRange(message, 16, message.length);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            return cipher.doFinal(ct);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Unable to decrypt message");
        }
    }
}
