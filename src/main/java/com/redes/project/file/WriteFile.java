/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.redes.project.file;

import com.redes.project.encrypt.EncryptFunctions;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author luizanurnberg
 */
public class WriteFile {

    public static void saveUserInFile(String userName, String userPassword) {
        try ( PrintWriter writer = new PrintWriter(new FileWriter("src/main/java/com/redes/project/file/userInfo.txt", true))) {
            Random rand = new Random();
            int userDelimiter = rand.nextInt(1000000);
            String userEmailInfo = "E-mail: " + userName;
            String userPasswordInfo = "Password: " + userPassword;

            writer.println("### USER DELIMITER ### " + userDelimiter);
            writer.println(userEmailInfo);
            writer.println(userPasswordInfo);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void saveKeyInFile(SecretKey secretkey) throws NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        try ( PrintWriter writer = new PrintWriter(new FileWriter("src/main/java/com/redes/project/file/keyInfo.txt", true))) {
            Random rand = new Random();
            EncryptFunctions encryptFunction = new EncryptFunctions();
            int keyDelimiter = rand.nextInt(1000000);
            String encryptedKey = encryptFunction.encryptAES_CBC(secretkey.toString(), secretkey);

            writer.println("### KEY DELIMITER ###: " + keyDelimiter);
            writer.println("Key: " + encryptedKey);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
        public static void saveIvInFile(String iv, SecretKey secretKey) throws NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        try ( PrintWriter writer = new PrintWriter(new FileWriter("src/main/java/com/redes/project/file/keyInfo.txt", true))) {
            Random rand = new Random();
            EncryptFunctions encryptFunction = new EncryptFunctions();
            int ivDelimiter = rand.nextInt(1000000);
            String encryptedIv = encryptFunction.encryptIV(iv, secretKey);

            writer.println("### IV DELIMITER ###: " + ivDelimiter);
            writer.println("IV: " + encryptedIv);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
