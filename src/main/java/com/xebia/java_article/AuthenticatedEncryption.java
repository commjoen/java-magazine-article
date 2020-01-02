package com.xebia.java_article;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Example of e
 */
public class AuthenticatedEncryption {

    public static void main(String[] args) {
        SecretKey secretKey = Utils.generateKeyForAES();
        SecretKey authenticationKey = Utils.generateKeyForHMAC();

        byte[] encryptedMsg = AES_CBC.encrypt(secretKey, "Java magazine article".getBytes());
        byte[] authentication = authenticateMessage(authenticationKey, encryptedMsg);
        byte[] authenticatedEncryptedMsg = ByteUtils.concatenate(encryptedMsg, authentication);

        System.out.println("Encrypted authenticated message is: " + Base64.getEncoder().encodeToString(authenticatedEncryptedMsg));
        System.out.println("Decrypting with authenticated message: " + new String(verifyAndDecryptMessage(secretKey, authenticationKey, authenticatedEncryptedMsg)));

        //Change a byte in the message
        authenticatedEncryptedMsg[17] = (byte) (authenticatedEncryptedMsg[0] - 1);
        System.out.println("Decrypting with authenticated message: " + verifyAndDecryptMessage(secretKey, authenticationKey, authenticatedEncryptedMsg));
    }

    private static byte[] authenticateMessage(SecretKey authenticationKey, byte[] msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(authenticationKey);
            return mac.doFinal(msg);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new CryptoException("Unable to authenticate");
        }
    }

    private static boolean verifyMessage(SecretKey authenticationKey, byte[] receivedAuthentication, byte[] msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");

            //Calculate authentication ourselves
            mac.init(authenticationKey);
            byte[] calculatedAuthentication = mac.doFinal(msg);

            //And compare them
            return org.bouncycastle.util.Arrays.constantTimeAreEqual(receivedAuthentication, calculatedAuthentication);
            //using a constant equals function otherwise we are again susceptible to a timing attack

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new CryptoException("Unable to verify");
        }
    }

    public static byte[] verifyAndDecryptMessage(SecretKey secretKey, SecretKey authenticationKey, byte[] msg) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");

            //First let's split of the authentication and part of the msg without authentication tag
            byte[] receivedAuthentication = Arrays.copyOfRange(msg, msg.length - mac.getMacLength(), msg.length);
            byte[] encryptedMsg = Arrays.copyOfRange(msg, 0, msg.length - mac.getMacLength());

            if (verifyMessage(authenticationKey, receivedAuthentication, encryptedMsg)) {
                return AES_CBC.decrypt(secretKey, encryptedMsg);
            } else {
                throw new CryptoException("MAC not correct");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Unable to decrypt message");
        }
    }
}
