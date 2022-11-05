package brute.server;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Random;

public class Main {
    static final int PORT_NUMBER = 8003;
    static int range = -1;
    static String hashPassword;
    static App app = new App();

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        JFrame frame = new JFrame("Сервер");
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

        hashPassword = generateARandomPasswordWithHash();

        app.textArea1.append("Хеш пароля: " + hashPassword +"\n");

        try(ServerSocket ss = new ServerSocket(PORT_NUMBER)) {
            app.textArea1.append("Ожидание клиента....\n");
            int id = 0;

            while (true) {
                Socket clientSocket = ss.accept();
                ClientServiceThread clientService = new ClientServiceThread(clientSocket, ++id);
                clientService.start();

                app.textArea1.append("\nКлиент_" + id + " подключён");

                if(clientSocket.isClosed()) break;
            }
        }

    }

    public static String generateARandomPasswordWithHash() throws NoSuchAlgorithmException {

        StringBuilder tmp = new StringBuilder();
        char[] symbols;
        char[] buffer = new char[5];
        String date = getSystemDate();
        Random random = SecureRandom.getInstanceStrong();
        StringBuilder sb = new StringBuilder();

        for (char ch = '0'; ch <= '9'; ++ch) {
            tmp.append(ch);
        }
        for (char ch = 'A'; ch <= 'Z'; ++ch) {
            tmp.append(ch);
        }
        symbols = tmp.toString().toCharArray();

        for (int index = 0; index < buffer.length; ++index) {
            buffer[index] = symbols[random.nextInt(symbols.length)];
        }

        try {
            String actualPassword = new String(buffer);
            app.textArea1.append("Пароль: " + actualPassword + "\n");

            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(( actualPassword + date).getBytes());
            byte[] byteData = md.digest();

            for (byte byteDatum : byteData) {
                sb.append(Integer.toString((byteDatum & 0xff) + 0x100, 16).substring(1));
            }
        } catch (NoSuchAlgorithmException ignored) {

        }

        return new String(sb);
    }

    public static String getSystemDate() {

        DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy");
        Calendar cal = Calendar.getInstance();
        return (dateFormat.format(cal.getTime()));
    }

    public static class ClientServiceThread extends Thread{

        int noOfDataSent = 1;
        int clientId = -1;
        String sendMsg = "";
        String receiveMsg = "";
        Socket clientSocket;

        ClientServiceThread(Socket socket, int id){
            clientSocket = socket;
            clientId = id;
        }

        /**
         * this method print client range and data packet in command prompt.
         * @param noOfDataSent
         * @param clientId
         */
        void printIntoSystem(int noOfDataSent, int clientId) {

            long lowerLimit = 1000000 * range; //1,000,000
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

            app.textArea1.append("\nПакет данных_" + noOfDataSent +" отправлен клиенту_" + clientId);
            app.textArea1.append("\nДан диапазон: от " +
                    sLowerLimit.toUpperCase() + " до " + sUpperLimit.toUpperCase());
        }

        @Override
        public void run() {
            try {
                BufferedReader brIN = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintStream psOUT = new PrintStream(clientSocket.getOutputStream());   //for writing

                while (noOfDataSent <= 4) {
                    sendMsg = (++range) + "\n" + hashPassword;
                    psOUT.println(sendMsg);
                    printIntoSystem(noOfDataSent, clientId);

                    receiveMsg = brIN.readLine();
                    if (receiveMsg.equals("success")) {
                        app.textArea1.append("\n Клиент_" + clientId + " взломал пароль \n");
                        clientSocket.close();
                        break;
                    }
                    noOfDataSent++;
                }

                clientSocket.close();
                brIN.close();
                psOUT.close();
                app.textArea1.append("\nРазорвано соединение с клиентом_" + clientId);

            } catch (IOException ignored) { }

        }
    }

}
