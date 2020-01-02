package com.xebia.java_article;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import static com.xebia.java_article.Utils.generateKeyForAES;

public class AES_CBC {

    public static void main(String[] args) {
        SecretKey secretKey = generateKeyForAES();

        byte[] encryptedMsg = encrypt(secretKey, "Java magazine article".getBytes());
        System.out.println("Encrypted message is: " + Base64.getEncoder().encodeToString(encryptedMsg));
        System.out.println("Decrypted message is: " + new String(decrypt(secretKey, encryptedMsg)));
    }

    public static byte[] encrypt(SecretKey secretKey, byte[] message) {
        try {
            //PKCS5Padding is for 8 bytes padding only but internally Java uses PKCS7Padding you can only specify "AES/CBC/PKCS7Padding"
            //if you add BouncyCastle as security provider you can use AES/CBC/PKCS7Padding directly
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            //Concatenate the IV and the encrypted message (IV MUST BE random)
            return ByteUtils.concatenate(cipher.getIV(), cipher.doFinal(message));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
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
