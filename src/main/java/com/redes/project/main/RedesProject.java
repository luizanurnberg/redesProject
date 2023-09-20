/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Project/Maven2/JavaApp/src/main/java/${packagePath}/${mainClassName}.java to edit this template
 */
package com.redes.project.main;

import com.redes.project.encrypt.KeyManager;
import com.redes.project.model.User;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author luizanurnberg
 */
public class RedesProject {

    public static void main(String[] args) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        Scanner scanner = new Scanner(System.in);
        KeyManager keyManager = new KeyManager();
        SecretKey secretKey = keyManager.getSecretKey();
        byte[] iv = keyManager.getIv();
        byte[] salt = keyManager.getSalt();
        boolean isLoggedIn = false;

        while (!isLoggedIn) {
            System.out.println("\n--- MENU ---\n");
            System.out.println("1 - Cadastrar um novo usuário");
            System.out.println("2 - Login");
            System.out.println("3 - Sair");
            System.out.print("Por favor, escolha uma opção: ");

            int choice = 0;
            try {
                choice = scanner.nextInt();
            } catch (java.util.InputMismatchException e) {
                System.out.println("Entrada inválida. Por favor, insira uma das opções disponíveis.");
                scanner.nextLine();
                continue;
            }
            scanner.nextLine();

            switch (choice) {
                case 1:
                    System.out.println("\n--- CADASTRO ---\n");
                    System.out.print("Digite o seu e-mail: ");
                    String userRegisterEmail = scanner.nextLine();
                    System.out.print("Digite a sua senha: ");
                    String userRegisterPassword = scanner.nextLine();
                    User userRegister = new User(userRegisterEmail, userRegisterPassword);
                    User.saveUserInfo(userRegister, secretKey, salt, iv);
                    System.out.print("Usuário cadastrado com sucesso.\n");
                    break;

                case 2:
                    System.out.println("\n--- LOGIN ---\n");
                    System.out.print("Digite o seu e-mail: ");
                    String userEmail = scanner.nextLine();
                    System.out.print("Digite a sua senha: ");
                    String userPassword = scanner.nextLine();
                    User userLogin = new User(userEmail, userPassword);

                    if (userLogin.compareUserInfo(userEmail, userPassword, secretKey, salt, iv) == true) {
                        System.out.println("Match: true");
                    } else {
                        System.out.println("Match: false");
                    }
                    break;

                case 3:
                    System.out.println("Saindo.");
                    System.exit(0);

                default:
                    System.out.println("Opção inválida.");
            }

        }

    }
}
