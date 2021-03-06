package com.xebia.java_article;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.bouncycastle.pqc.math.linearalgebra.ByteUtils.concatenate;
import static org.bouncycastle.util.encoders.Hex.decode;

public class PredicatableIV {

    private static byte[] secretKey = {109, 121, 95, 115, 117, 112, 101, 114, 95, 115, 101, 99, 95, 107, 101, 121};

    /**
     * Below you will see two tests, 1 where we do not have to deal with padding, the other one is where we
     * have a short message so we need to take the padding into account while creating our message
     * This example shows how re-using the same IV can give you trouble.
     */
    public static void main(String[] args) throws Exception {
        exactly16BytesMessage();
        shorterMessageNeedToIncludePadding();
    }

    public static void exactly16BytesMessage() throws Exception {
        //As we touched upon in our previous article the IV + cipher text is distributed among 2 parties IV is not a secret
        byte[] ivAlice = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        byte[] cipherTextAlice = encrypt("It is a test msg".getBytes(), secretKey, ivAlice);

        //Mallory for example can start guessing the value can be a constant, remember Mallory could be using the application as a normal user as well
        byte[] ivMallory = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2};
        byte[] plainTextMallory = xor("It is a test msg".getBytes(), xor(ivMallory, ivAlice));

        byte[] cipherTextMallory = encrypt(plainTextMallory, secretKey, ivMallory);

        System.out.println(toHex(cipherTextAlice));
        System.out.println(toHex(cipherTextMallory));
    }

    public static void shorterMessageNeedToIncludePadding() throws Exception {
        byte[] ivAlice = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        byte[] cipherTextAlice = encrypt("married".getBytes(), secretKey, ivAlice);

        //Mallory for example can start guessing the value can be a constant, remember Mallory could be using the application as a normal user as well
        byte[] ivMallory = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2};

        //The plain text will be padded before encryption we need to add this in our plaintext as well
        //Since we are using PKCS7Padding we and the message has length 12 we need to add 04 04 04 04 as padding
        //to the message
        byte[] plainTextMallory = xor(xor(ivMallory, ivAlice), concatenate("married".getBytes(), decode("090909090909090909")));
        byte[] cipherTextMallory = encrypt(plainTextMallory, secretKey, ivMallory);

        System.out.println(toHex(cipherTextAlice));
        System.out.println(toHex(cipherTextMallory));
        //the encrypted message will contain an extra block containing padding which we can ignore due to Mallory's message
        //being exactly 16 bytes
    }

    /**
     * Encrypt, this is the part which would normally happen in the application, the parameter guessedIv will of
     * course not be supplied by Mallory but would be generated by the application.
     */
    private static byte[] encrypt(byte[] plaintext, byte[] key, byte[] guessedIv) throws Exception {
        IvParameterSpec ivSpec = new IvParameterSpec(guessedIv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(ENCRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[Math.min(a.length, b.length)];

        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }

        return result;
    }

    public static String toHex(byte[] b) {
        return new String(Hex.encode(b));
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}

