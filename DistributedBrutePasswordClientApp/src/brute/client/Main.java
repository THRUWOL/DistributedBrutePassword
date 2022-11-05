package brute.client;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {
    static App app = new App();
    static final int PORT_NUMBER = 8003;
    static final String SERVER_IP = "127.0.0.1"; // localhost

    static int clientTrialNumber = 0;
    static String date;
    static String actualHashPassword;
    static BufferedReader brIN;
    static PrintStream psOUT;
    static Socket clientSocket;
    static MessageDigest md;
    static String messageSentToServer;
    static int range;

    public static void main(String[] args) {
        JFrame frame = new JFrame("Клиент");
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();

        int screenWidth = screenSize.width/2;
        int screenHeight = screenSize.height/2;

        frame.setContentPane(app.panel1);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
        frame.setLocationRelativeTo(null);
        frame.setSize(screenWidth, screenHeight);

        app.textArea1.append("Распределённый взломщик паролей MD5\n");

        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }

        date = getSystemDate();

        getConnectedToServer();
        clientTrialNumber++;
        while(clientTrialNumber <= 4){

            range = getRangeFromServer();
            printIntoSystem(clientTrialNumber);
            messageSentToServer = doCrackingPassword();

            if(messageSentToServer.equals("fail")){
                app.textArea1.append("\nНе могу найти пароль.");
                if(clientTrialNumber != 4) app.textArea1.append(" запрос на другой пакет...");

                psOUT.println(messageSentToServer);
                clientTrialNumber++;
            }else{
                app.textArea1.append("Получил пароль. Это: " + messageSentToServer);
                psOUT.println("success");
                while(true){}
            }
        }
        getDisconnectedFromServer();
    }

    public static String doCrackingPassword(){

        String value;
        String temp;
        String generatedHash;

        long upperLimit;

        long lowerLimit = 1000000L * range; //1,000,000
        upperLimit = lowerLimit + (1000000-1);

        for (long i = lowerLimit; i <= upperLimit; i++) {
            value = Long.toString(i, 36);
            StringBuilder sb = new StringBuilder(value);

            //if generating password is less than 5 character
            if ((value.length()) < 5) {
                for (int j = 0; j < 5 - (value.length()); j++) {
                    sb.insert(j, "0");
                }

                temp = sb.toString().toUpperCase();

            } else {
                temp = value.toUpperCase();
            }
            generatedHash = generateHash(temp);

            if(compareHash(actualHashPassword, generatedHash)){
                return temp;
            }
        }

        return "fail";
    }

    public static String getSystemDate(){

        DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy");
        Calendar cal = Calendar.getInstance();
        return (dateFormat.format(cal.getTime()));
    }

    public static String generateHash(String crackPassword) {

        byte[] byteData;
        StringBuilder sb = new StringBuilder();
        md.update((crackPassword + date).getBytes());
        byteData = md.digest();

        for (byte byteDatum : byteData) {
            sb.append(Integer.toString((byteDatum & 0xff) + 0x100, 16).substring(1));
        }
        return new String(sb);
    }

    public static boolean compareHash(String givenHash, String generatedHash){
        return givenHash.equals(generatedHash);
    }

    public static void getConnectedToServer() {
        try {
            clientSocket = new Socket(SERVER_IP, PORT_NUMBER);
            app.textArea1.append("Установлено соединение с сервером\n");

            brIN = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            psOUT = new PrintStream(clientSocket.getOutputStream());   //for writing
        } catch (IOException ex) {

        }
    }

    public static void getDisconnectedFromServer(){
        try {
            clientSocket.close();
            brIN.close();
            psOUT.close();
            app.textArea1.append("\nПотеряно соединение с сервером");
        } catch (IOException ex) {

        }
    }


    public static int getRangeFromServer(){
        String receiveRange = "";
        try {
            receiveRange = brIN.readLine();
            actualHashPassword = brIN.readLine();

        } catch (IOException ex) {
        }

        return Integer.parseInt(receiveRange);
    }

    public static void printIntoSystem(int dataReceiveNo) {

        long lowerLimit = 1000000L * range; //1,000,000
        long upperLimit = lowerLimit + (1000000 - 1);

        String sLowerLimit = Long.toString(lowerLimit, 36);
        String sUpperLimit = Long.toString(upperLimit, 36);

        if ((sLowerLimit.length()) < 5) {

            StringBuilder sb = new StringBuilder(sLowerLimit);
            for (int j = 0; j < 5 - (sLowerLimit.length()); j++) {
                sb.insert(j, "0");
            }

            sLowerLimit = sb.toString().toUpperCase();
        }

        if ((sUpperLimit.length()) < 5) {

            StringBuilder sb = new StringBuilder(sUpperLimit);
            for (int j = 0; j < 5 - (sUpperLimit.length()); j++) {
                sb.insert(j, "0");
            }

            sUpperLimit = sb.toString().toUpperCase();
        }

        app.textArea1.append("\n" + "\nПолучить пакет данных_" + dataReceiveNo +" с сервера");
        app.textArea1.append("\nНачинаю взламывать пароль с заданным диапазоном: " +
                sLowerLimit.toUpperCase() + " to " + sUpperLimit.toUpperCase());
    }
}
