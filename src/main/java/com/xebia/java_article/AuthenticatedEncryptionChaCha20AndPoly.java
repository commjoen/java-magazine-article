package com.xebia.java_article;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import static org.bouncycastle.pqc.math.linearalgebra.ByteUtils.concatenate;

public class AuthenticatedEncryptionChaCha20AndPoly {

    public static void main(String[] args) {
        SecretKey secretKey = Utils.generateKeyForChaCha20();

        byte[] authenticatedEncryptedMsg = encrypt(secretKey, "Java magazine article".getBytes(), "tag".getBytes());
        System.out.println("Encrypted authenticated message is: " + Base64.getEncoder().encodeToString(authenticatedEncryptedMsg));
        System.out.println("Decrypting with authenticated message: " + new String(decrypt(secretKey, authenticatedEncryptedMsg, "tag".getBytes())));

        //Specify incorrect tag
        System.out.println("Decrypting with authenticated message: " + new String(decrypt(secretKey, authenticatedEncryptedMsg, "wrong_tag".getBytes())));
    }

    private static byte[] encrypt(SecretKey secretKey, byte[] msg, byte[] associatedData) {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            if (associatedData != null) {
                cipher.updateAAD(associatedData);
            }

            return concatenate(cipher.getIV(), cipher.doFinal(msg));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Unable to authenticate");
        }
    }

    public static byte[] decrypt(SecretKey secretKey, byte[] msg, byte[] associatedData) {
        try {
            byte[] nonce = Arrays.copyOfRange(msg, 0, 12);
            byte[] ct = Arrays.copyOfRange(msg, 12, msg.length);

            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(nonce));
            if (associatedData != null) {
                cipher.updateAAD(associatedData);
            }

            return cipher.doFinal(ct);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Unable to decrypt message");
        }
    }
}
