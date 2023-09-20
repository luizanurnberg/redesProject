/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.redes.project.encrypt;

import com.redes.project.file.WriteFile;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author luizanurnberg
 */
public class KeyManager {

    private SecretKey secretKey;
    private SecretKey masterSecretKey;
    private byte[] salt;
    private byte[] ivBytes;

    public KeyManager() throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        keyGenerator.init(256);
        this.secretKey = keyGenerator.generateKey();
        this.masterSecretKey = keyGenerator.generateKey();
        this.ivBytes = new byte[16];
        random.nextBytes(this.ivBytes);

        WriteFile.saveKeyInFile(this.secretKey.toString(), this.masterSecretKey, this.ivBytes);
        WriteFile.saveIvInFile(Arrays.toString(this.ivBytes), this.secretKey);
    }

    public byte[] generateSalt() {
        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            return salt;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String derivePassword(String password, byte[] salt) throws InvalidKeySpecException {
        try {
            int iterations = 10000;
            int keyLength = 256;

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
            byte[] hash = factory.generateSecret(spec).getEncoded();

            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public SecretKey getMasterSecretKey() {
        if (masterSecretKey == null) {
            throw new IllegalStateException("Secret key não foi inicializada.");
        }
        return this.masterSecretKey;
    }

    public byte[] getIv() {
        return this.ivBytes;
    }

    public byte[] getSalt() {
        if (salt == null) {
            salt = this.generateSalt();
        }
        return salt;
    }

    public SecretKey getSecretKey() {
        if (secretKey == null) {
            throw new IllegalStateException("Secret key não foi inicializada.");
        }
        return this.secretKey;
    }

}
