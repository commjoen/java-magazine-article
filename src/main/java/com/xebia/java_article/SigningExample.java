package com.xebia.java_article;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class SigningExample {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        byte[] msg = "Java magazine article".getBytes();
        byte[] signature = signRsaPssSha512(keyPair.getPrivate().getEncoded(), msg);
        System.out.println("Signature is valid: " + verifySignedMessage(keyPair.getPublic().getEncoded(), msg, signature));

        //Change the signature
        byte[] manipulatedSignature = Arrays.copyOf(signature, signature.length);
        manipulatedSignature[0] = manipulatedSignature[1];
        System.out.println("Signature is valid: " + verifySignedMessage(keyPair.getPublic().getEncoded(), msg, manipulatedSignature));

        //Change the message
        msg = "Java Magazine article".getBytes();
        System.out.println("Signature is valid: " + verifySignedMessage(keyPair.getPublic().getEncoded(), msg, manipulatedSignature));
    }

    public static byte[] signRsaPssSha512(byte[] privateKey, byte[] msg) {
        PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA512Digest(), new SHA512Digest(), new SHA512Digest().getDigestSize());
        try {
            RSAPrivateCrtKeyParameters key = (RSAPrivateCrtKeyParameters) PrivateKeyFactory.createKey(privateKey);
            signer.init(true, key);
            signer.update(msg, 0, msg.length);
            return signer.generateSignature();
        } catch (IOException | CryptoException e) {
            throw new IllegalStateException(e);
        }
    }

    public static boolean verifySignedMessage(byte[] publicKey, byte[] msg, byte[] signature) {
        PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA512Digest(), new SHA512Digest(), new SHA512Digest().getDigestSize());
        try {
            AsymmetricKeyParameter key = PublicKeyFactory.createKey(publicKey);
            signer.init(true, key);
            signer.update(msg, 0, msg.length);
            return signer.verifySignature(signature);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

}
