package com.xebia.java_article;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

import static com.xebia.java_article.Utils.generateRsaKeyPair;

public class RSAEncryption {

    public static void main(String[] args) {
        KeyPair keyPair = generateRsaKeyPair();

        byte[] encryptedMsg = encrypt(keyPair.getPublic(), "Java magazine article".getBytes());
        System.out.println("Encrypted message is: " + Base64.getEncoder().encodeToString(encryptedMsg));
        System.out.println("Decrypted message is: " + new String(decrypt(keyPair.getPrivate(), encryptedMsg)));

        //Only limited to encrypt messages up to length of key, we use 2048 so let's encrypt a longer message
        //See https://crypto.stackexchange.com/questions/42097/what-is-the-maximum-size-of-the-plaintext-message-for-rsa-oaep/42100#42100 for
        //an overview of how much the padding overhead is per algorithm
        byte[] msg = new byte[190]; //max
        new SecureRandom().nextBytes(msg);
        encrypt(keyPair.getPublic(), msg);

        msg = new byte[191]; //too much data
        new SecureRandom().nextBytes(msg);
        encrypt(keyPair.getPublic(), msg);
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] message) {
        try {
            //Note: both PKCS#1v1.5 padding and no padding are insecure as you are susceptible to a padding oracle attack. 
            //We will talk a bit more about this in our second article
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Unable to encrypt");
        }
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(message);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Unable to decrypt");
        }
    }

}
