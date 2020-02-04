package com.xebia.java_article;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

import static com.xebia.java_article.Utils.generateIV;
import static com.xebia.java_article.Utils.generateKeyForAES;

public class AES_GCM {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        //Generate a 256 bits key, the key defines the strength of the AES encryption, possible values: AES-128/AES-192 and AES-256
        SecretKey secretKey = generateKeyForAES();

        var encryptedMsg = encryptWithIvSpec(secretKey, "Java magazine article".getBytes());
        System.out.println("Encrypted with IV spec message is: " + Base64.getEncoder().encodeToString(encryptedMsg));
        System.out.println("Decrypted with IV spec message is: " + new String(decryptWithIvSpec(secretKey, encryptedMsg)));

        encryptedMsg = encryptWithGcmSpec(secretKey, "Java magazine article".getBytes(), 128);
        System.out.println("Encrypted with GCM spec message is: " + Base64.getEncoder().encodeToString(encryptedMsg));
        System.out.println("Decrypted with IV spec message is: " + new String(decryptWithIvSpec(secretKey, encryptedMsg)));

        encryptedMsg = encryptWithIvSpec(secretKey, "Java magazine article".getBytes());
        System.out.println("Encrypted with IV spec message is: " + Base64.getEncoder().encodeToString(encryptedMsg));
        System.out.println("Decrypted with GCM spec message is: " + new String(decryptWithGcmSpec(secretKey, encryptedMsg, 128)));

        encryptedMsg = encryptWithGcmSpec(secretKey, "Java magazine article".getBytes(), 128);
        System.out.println("Encrypted with GCM spec message is: " + Base64.getEncoder().encodeToString(encryptedMsg));
        System.out.println("Decrypted with GCM spec message is: " + new String(decryptWithGcmSpec(secretKey, encryptedMsg, 128)));

        encryptedMsg = encryptWithGcmSpec(secretKey, "Java magazine article".getBytes(), 128);
        System.out.println("Encrypted with GCM spec message is: " + Base64.getEncoder().encodeToString(encryptedMsg));
        System.out.println("Decrypted with GCM spec message is: " + new String(decryptWithGcmSpec(secretKey, encryptedMsg, 128)));

        //The following DOES NOT work, by default IV parameter spec uses 128 for tag length and we specify 96
        encryptedMsg = encryptWithGcmSpec(secretKey, "Java magazine article".getBytes(), 96);
        System.out.println("Encrypted with GCM spec message is: " + Base64.getEncoder().encodeToString(encryptedMsg));
        System.out.println("Decrypted with GCM spec message is: " + new String(decryptWithIvSpec(secretKey, encryptedMsg)));
    }

    public static byte[] encryptWithGcmSpec(SecretKey secretKey, byte[] message, int tagLength) {
        try {
            //Generate the IV yourself, as Cipher.getIV() might return a non random one it all depends on the underlying security provider
            var iv = generateIV(12);

            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, iv));

            //Concatenate the IV and the encrypted message (IV MUST BE random)
            return ByteUtils.concatenate(iv, cipher.doFinal(message));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            // Never ever leak details about what went wrong during the encryption / decryption otherwise you might be
            // vulnerable to a padding oracle attack, timing attack etc.
            throw new CryptoException("Unable to encrypt message");
        }
    }

    public static byte[] decryptWithGcmSpec(SecretKey secretKey, byte[] message, int tagLength) {
        try {
            //First split the IV and cipher text
            byte[] iv = Arrays.copyOfRange(message, 0, 12);
            byte[] ct = Arrays.copyOfRange(message, 12, message.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(tagLength, iv));
            return cipher.doFinal(ct);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Unable to decrypt message");
        }
    }

    public static byte[] encryptWithIvSpec(SecretKey secretKey, byte[] message) {
        try {
            //Generate the IV yourself, as Cipher.getIV() might return a non random one it all depends on the underlying security provider
            var iv = generateIV(12);

            var cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv)); //Only BC allows this spec

            //Concatenate the IV and the encrypted message (IV MUST BE random)
            return ByteUtils.concatenate(iv, cipher.doFinal(message));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
            // Never ever leak details about what went wrong during the encryption / decryption otherwise you might be
            // vulnerable to a padding oracle attack, timing attack etc.
            throw new CryptoException("Unable to encrypt message");
        }
    }

    public static byte[] decryptWithIvSpec(SecretKey secretKey, byte[] message) {
        try {
            //First split the IV and cipher text
            byte[] iv = Arrays.copyOfRange(message, 0, 12);
            byte[] ct = Arrays.copyOfRange(message, 12, message.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            return cipher.doFinal(ct);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Unable to decrypt message");
        }
    }

}
