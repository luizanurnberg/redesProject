/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.redes.project.model;

import com.redes.project.encrypt.EncryptFunctions;
import com.redes.project.encrypt.KeyManager;
import static com.redes.project.encrypt.KeyManager.derivePassword;
import com.redes.project.file.WriteFile;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.UUID;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

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

    public static void saveUserInfo(User user) throws InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        EncryptFunctions encryptFunction = new EncryptFunctions();
        SecretKey secretKey = KeyManager.getSecretKey();
        WriteFile userInfo = new WriteFile();
        byte[] salt = KeyManager.getSalt();
        
        String derivedPassword = derivePassword(user.getPassword(), salt);
        String encryptedEmail = encryptFunction.hashSHA256(user.getEmail());
        String encryptedPassword = encryptFunction.encryptAES_CBC(derivedPassword, secretKey);
        
        String userEmailInfo = encryptedEmail;
        String userPasswordInfo = encryptedPassword;
        userInfo.saveUserInFile(userEmailInfo, userPasswordInfo);
    }

    public static boolean compareUserInfo(String userEmail, String userPassword) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        try ( BufferedReader br = new BufferedReader(new FileReader("src/main/java/com/redes/project/file/userInfo.txt"))) {
            String line;
            boolean emailMatch = false;
            boolean passwordMatch = false;

            while ((line = br.readLine()) != null) {
                if (line.startsWith("E-mail: ")) {
                    String encryptedEmailHash = line.substring(8);
                    String providedEmailHash = EncryptFunctions.hashSHA256(userEmail);

                    if (encryptedEmailHash.equals(providedEmailHash)) {
                        emailMatch = true;
                    }
                }
                if (line.startsWith("Password: ")) {
                    String encryptedPassword = line.substring(10);
                    SecretKey secretKey = KeyManager.getSecretKey();
                    byte[] salt = KeyManager.getSalt();

                    String reproducedDerivedPassword = derivePassword(userPassword, salt);
                    String decryptedPassword = EncryptFunctions.decryptAES_CBC(encryptedPassword, secretKey);

                    if (reproducedDerivedPassword.equals(decryptedPassword)) {
                        passwordMatch = true;
                    }

                }
            }

            return emailMatch && passwordMatch;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

}
