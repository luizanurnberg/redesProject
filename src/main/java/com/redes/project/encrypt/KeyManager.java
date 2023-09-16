/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.redes.project.encrypt;

import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 *
 * @author luizanurnberg
 */

public class KeyManager {

    private static SecretKey secretKey;
    
    public static void initializeSecretKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            secretKey = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static SecretKey getSecretKey() {
        if (secretKey == null) {
            throw new IllegalStateException("Secret key not initialized. Call initializeSecretKey() first.");
        }
        return secretKey;
    }
}

