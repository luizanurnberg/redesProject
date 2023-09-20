/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.redes.project.model;

import com.redes.project.encrypt.EncryptFunctions;
import static com.redes.project.encrypt.KeyManager.derivePassword;
import com.redes.project.file.WriteFile;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author luizanurnberg
 */
public class User {

    private String email;
    private String password;

    public User(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

    public static void saveUserInfo(User user, SecretKey secretKey, byte[] salt, byte[] iv) throws InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        try {
            String derivedPassword = derivePassword(user.getPassword(), salt);
            String encryptedEmail = EncryptFunctions.hashSHA256(user.getEmail());
            String encryptedPassword = EncryptFunctions.encryptAES_CBC(derivedPassword, secretKey, iv);

            String userEmailInfo = encryptedEmail;
            String userPasswordInfo = encryptedPassword;
            WriteFile.saveUserInFile(userEmailInfo, userPasswordInfo);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean compareUserInfo(String userEmail, String userPassword, SecretKey secretKey, byte[] salt, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
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
                    String reproducedDerivedPassword = derivePassword(userPassword, salt);
                    String decryptedPassword = EncryptFunctions.encryptAES_CBC(reproducedDerivedPassword, secretKey, iv);

                    if (encryptedPassword.equals(decryptedPassword)) {
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
