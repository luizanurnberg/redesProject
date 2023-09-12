/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.redes.project.model;

import com.redes.project.encrypt.EncryptFunctions;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.UUID;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author luizanurnberg
 */
public class User {

    private String id;
    private String email;
    private String password;

    public User(String email, String password) {
        this.id = generateRandomUserId();
        this.email = email;
        this.password = password;
    }

    public String getId() {
        return id;
    }

    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

    private String generateRandomUserId() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString();
    }

    public static void saveUserInfo(User user) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException {
        try ( PrintWriter writer = new PrintWriter(new FileWriter("src/main/java/com/redes/project/model/userInfo.txt"), true)) {
            
            EncryptFunctions encryptFunction = new EncryptFunctions();
            
            String encryptedEmail = encryptFunction.hashSHA256(user.getEmail());
            String encryptedPassword = encryptFunction.encryptAES_CBC(user.getPassword());
            String userInfo = "UserId: " + user.getId() + " | E-mail: " + encryptedEmail + " | Password: " + encryptedPassword;
            
            writer.println(userInfo);
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean compareUserInfo() {
        return true;
    }
}
