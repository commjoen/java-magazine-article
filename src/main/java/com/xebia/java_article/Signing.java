package com.xebia.java_article;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import static com.xebia.java_article.Utils.generateRsaKeyPair;

public class Signing {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        KeyPair keyPair = generateRsaKeyPair();
        byte[] message = "Java magazine article example".getBytes(StandardCharsets.UTF_8);

        //Place signature and validate
        byte[] signature = sign(message, keyPair.getPrivate());
        System.out.println("Signature correct? " + verify(message, signature, keyPair.getPublic()));

        //Change signature
        signature[0] = signature[1];
        signature[1] = signature[2];
        System.out.println("Signature correct? " + verify(message, signature, keyPair.getPublic()));
    }

    private static byte[] sign(byte[] message, PrivateKey privateKey) {

        try {
            Signature signer = Signature.getInstance("SHA256withRSA/PSS");

            //See https://www.ietf.org/rfc/rfc3447.txt for description of the PSSParameterSpec
            signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));

            signer.initSign(privateKey, new SecureRandom());
            signer.update(message);
            return signer.sign();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | SignatureException | InvalidKeyException e) {
            throw new CryptoException("Signing failed");
        }
    }

    private static boolean verify(byte[] message, byte[] signature, PublicKey publicKey) {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA/PSS");
            signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            signer.initVerify(publicKey);
            signer.update(message);
            return signer.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | SignatureException | InvalidKeyException e) {
            throw new CryptoException("Signature verification failed");
        }
    }
}
