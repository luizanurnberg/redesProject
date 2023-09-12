/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Project/Maven2/JavaApp/src/main/java/${packagePath}/${mainClassName}.java to edit this template
 */

package com.redes.project.main;

import com.redes.project.model.User;
import java.util.Scanner;

/**
 *
 * @author luizanurnberg
 */
public class RedesProject {

    public static void main(String[] args) {
        
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("--- CADASTRO --- ");
        System.out.print("Digite o seu e-mail: ");
        String userRegisterEmail = scanner.nextLine();
        System.out.print("Digite a sua senha: ");
        String userRegisterPassword = scanner.nextLine();
        User userRegister = new User(userRegisterEmail, userRegisterPassword);
        User.saveUserInfo(userRegister);
        
        System.out.println("--- LOGIN --- ");
        System.out.print("Digite o seu e-mail: ");
        String userEmail = scanner.nextLine();
        System.out.print("Digite a sua senha: ");
        String userPassword = scanner.nextLine();
        User userLogin = new User(userEmail, userPassword);
        
        if(User.compareUserInfo() == true){
            System.out.println("Match: true");
        } else {
            System.out.println("Match: false");
        }
        
    }
}

