package com.xebia.java_article;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.sql.SQLOutput;
import java.util.Arrays;

public class FunWithProviders {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Adding a security provider will only add it as the last element of in the list of available security providers
     */
    public static void main(String[] args) throws Exception {
        // You can find them in JAVA_HOME/conf/security/java.security
        System.out.println("Start listing all security providers");
        Arrays.asList(Security.getProviders()).forEach(provider -> System.out.println(provider.getName()));
        System.out.println("End listing all security providers");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        System.out.println("The following provider is used: " + cipher.getProvider()); //will print SunJCE version 11

        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        System.out.println("The following provider is used: " + cipher.getProvider()); //will print BC version 1.6

        Security.removeProvider(new BouncyCastleProvider().getName());
        Security.insertProviderAt(new BouncyCastleProvider(), 1); // BE AWARE: 1 is the first position not 0
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        System.out.println("The following provider is used: " + cipher.getProvider()); //will print BC version 1.6
    }
}
