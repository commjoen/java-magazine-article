package com.xebia.java_article.change_cipher;

import java.util.Base64;

/**
 * Suppose you intercept the following messages from the Maze:
 *
 * <tt>
 * Received command: 0K8yMwTCcqBvPdVKXZ4RbGhDy/v4e8T4dTQSYWAzwcs=
 * Moving one position: DOWN
 * </tt>
 *
 * <p>
 * Let's try to construct a new message of our choice and send it to the Maze.
 * Of course this is a simplified example but just to illustrate how it can work
 * in a real application.
 */
public class ChangeCipher {

    public static void main(String[] args) {
        String interceptedCommand = "0K8yMwTCcqBvPdVKXZ4RbGhDy/v4e8T4dTQSYWAzwcs=";
        byte[] encryptedMsg = Base64.getDecoder().decode(interceptedCommand);

        //In AES CBC the first block is decrypted as follows: P1 = D(k, C1) XOR IV
        //So if we flip a bit in the IV it is directly visible in the decrypted plaintext so let's try this:

        encryptedMsg[0] = (byte) ("D".getBytes()[0] ^ "L".getBytes()[0] ^ encryptedMsg[0]);
        encryptedMsg[1] = (byte) ("O".getBytes()[0] ^ "E".getBytes()[0] ^ encryptedMsg[1]);
        encryptedMsg[2] = (byte) ("W".getBytes()[0] ^ "F".getBytes()[0] ^ encryptedMsg[2]);
        encryptedMsg[3] = (byte) ("N".getBytes()[0] ^ "T".getBytes()[0] ^ encryptedMsg[3]);

        Maze.walk(encryptedMsg);

        //This requires knowledge of the system and messages, but often the start of a message is static which
        //can lead to these kind of attacks.

        //Solution: Add authentication to the ciphertext!!
    }
}
