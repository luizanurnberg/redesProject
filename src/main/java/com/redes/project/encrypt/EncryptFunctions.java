/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.redes.project.encrypt;

import com.redes.project.file.WriteFile;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author luizanurnberg
 */
public class EncryptFunctions {

    public static String hashSHA256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encryptAES_CBC(String input, SecretKey secretKey) throws NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        try {
            byte[] ivBytes = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(ivBytes);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            WriteFile ivInfo = new WriteFile();
            ivInfo.saveIvInFile(ivSpec.toString(), secretKey);

            byte[] encryptedPasswordBytes = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[ivBytes.length + encryptedPasswordBytes.length];
            System.arraycopy(ivBytes, 0, combined, 0, ivBytes.length);
            System.arraycopy(encryptedPasswordBytes, 0, combined, ivBytes.length, encryptedPasswordBytes.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decryptAES_CBC(String encryptedText, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] ivBytes = Arrays.copyOfRange(encryptedBytes, 0, 16);

            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] decryptedPasswordBytes = cipher.doFinal(encryptedBytes, 16, encryptedBytes.length - 16);

            return new String(decryptedPasswordBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

//    public static String derivePassword(String password, byte[] salt) throws InvalidKeySpecException {
//        try {
//            int iterations = 10000;
//            int keyLength = 256;
//            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
//            byte[] hash = factory.generateSecret(spec).getEncoded();
//            return Base64.getEncoder().encodeToString(hash);
//        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
//            e.printStackTrace();
//            return null;
//        }
//    }

    public static String encryptIV(String input, SecretKey secretKey) throws NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        try {
            byte[] ivBytes = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(ivBytes);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            byte[] encryptedPasswordBytes = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[ivBytes.length + encryptedPasswordBytes.length];
            System.arraycopy(ivBytes, 0, combined, 0, ivBytes.length);
            System.arraycopy(encryptedPasswordBytes, 0, combined, ivBytes.length, encryptedPasswordBytes.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }
}
