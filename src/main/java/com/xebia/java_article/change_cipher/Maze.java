package com.xebia.java_article.change_cipher;

import com.xebia.java_article.AES_CBC;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class Maze {

    enum Command {
        LEFT, RIGHT, UP, DOWN
    }

    private static SecretKey secretKey = new SecretKeySpec(
            new byte[]{109, 121, 95, 115, 117, 112, 101, 114, 95, 115, 101, 99, 95, 107, 101, 121}, "AES");

    public static void walk(byte[] encryptedCommand) {
        System.out.println("Received command: " + Base64.getEncoder().encodeToString(encryptedCommand));
        System.out.println("Moving one position: " + new String(AES_CBC.decrypt(secretKey, encryptedCommand)));
    }

    public static void main(String[] args) {
        walk(AES_CBC.encrypt(secretKey, Command.UP.toString().getBytes()));
        walk(AES_CBC.encrypt(secretKey, Command.UP.toString().getBytes()));
        walk(AES_CBC.encrypt(secretKey, Command.LEFT.toString().getBytes()));
        walk(AES_CBC.encrypt(secretKey, Command.UP.toString().getBytes()));
        walk(AES_CBC.encrypt(secretKey, Command.DOWN.toString().getBytes()));
        walk(AES_CBC.encrypt(secretKey, Command.DOWN.toString().getBytes()));
        walk(AES_CBC.encrypt(secretKey, Command.RIGHT.toString().getBytes()));
    }
}
