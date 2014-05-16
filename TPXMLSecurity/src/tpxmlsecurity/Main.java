/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package tpxmlsecurity;

import java.util.Scanner;

/**
 *
 * @author mathieu
 */
public class Main {
    public static void main(String[] args) throws Exception {
        SignatureDetachee detachee = new SignatureDetachee();
        SignatureEnveloppee enveloppee = new SignatureEnveloppee();
        SignatureEnveloppante enveloppante = new SignatureEnveloppante();
        Validation validation = new Validation();
        
        int choix = 0;
        while(choix != 5) {
            System.out.println("1 : Creer signature detachee");
            System.out.println("2 : Creer signature enveloppee");
            System.out.println("3 : Creer signature enveloppante");
            System.out.println("4 : Valider document XML");
            System.out.println("5 : Quitter");
            Scanner sc = new Scanner(System.in);
            choix = sc.nextInt();
            String nomFichier, resultat;
            switch(choix) {
                case 1:
                    System.out.println("Nom du fichier resultat ?");
                    resultat = sc.next();
                    detachee.detachee(resultat);
                break;
                case 2:
                    System.out.println("Nom du fichier à signer ?");
                    nomFichier = sc.next();
                    System.out.println("Nom du fichier resultat ?");
                    resultat = sc.next();
                    enveloppee.enveloppee(nomFichier, resultat);
                break;
                case 3:
                    System.out.println("Nom du fichier à signer ?");
                    nomFichier = sc.next();
                    System.out.println("Nom du fichier resultat ?");
                    resultat = sc.next();
                    enveloppante.enveloppante(nomFichier, resultat);
                break;
                case 4:
                    System.out.println("Nom du fichier à valider ?");
                    nomFichier = sc.next();
                    validation.validation(nomFichier);
                break;

            }
            
        }
    }
}
