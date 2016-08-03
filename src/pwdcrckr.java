import org.apache.commons.io.Charsets;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class pwdcrckr {

    private final String FILEPATH_WORST_PASSWORDS = getClass().getResource("500-worst-passwords.txt").getPath();
    private final String FILEPATH_PASSWD = getClass().getResource("passwd.txt").getPath();
    private final String FILEPATH_SHADOW = getClass().getResource("shadow.txt").getPath();
    private final static String LINE_SEPARATOR = "\r\n";
    private final static String USERINFO_SEPARATOR = ":";

    private String[] worstPasswords;
    private final List<User> users = new ArrayList<>();

    private File fileOutput;

    public static void main(String[] args) {
        System.out.println("Starting now");
        final long startTime = System.currentTimeMillis();

        pwdcrckr pwdcrckr = new pwdcrckr();
        try {
            pwdcrckr.getWorstPasswords();
            pwdcrckr.getUsers();
            pwdcrckr.getPasswords();
            pwdcrckr.performCracking();
            pwdcrckr.displayResults();
        } catch (Exception e) {
            e.printStackTrace();
        }

        final long duration = System.currentTimeMillis() - startTime;
        System.out.println("Execution time: " + (duration / 1000) + " seconds");

    }

    private pwdcrckr() {
        fileOutput = new File("./results.txt");
    }

    private void getWorstPasswords() throws IOException {
        String strWorstPasswords = FileUtils.readFileToString(new File(FILEPATH_WORST_PASSWORDS), Charsets.UTF_8);
        worstPasswords = strWorstPasswords.split(LINE_SEPARATOR);
    }

    private void getUsers() throws IOException {
        // 1. Get one line of user info e.g. root:x:0:0:root:/root:/bin/bash
        String strUsers = FileUtils.readFileToString(new File(FILEPATH_PASSWD), Charsets.UTF_8);
        String[] tempUsers = strUsers.split(LINE_SEPARATOR);

        // 2. Split the fields by : and get the needed values
        for (String tempUser : tempUsers) {
            String[] fields = tempUser.split(USERINFO_SEPARATOR);
            int userId = Integer.parseInt(fields[2]);
            if (userId > 1000) { // Is it > or >= ???
                User user = new User();
                user.username = fields[0];
                user.userId = Integer.parseInt(fields[2]);
                users.add(user);
            }
        }
    }

    private void getPasswords() throws IOException {
        // 1. Get one line of user info e.g. root:x:0:0:root:/root:/bin/bash
        String strUsers = FileUtils.readFileToString(new File(FILEPATH_SHADOW), Charsets.UTF_8);
        String[] tempShadows = strUsers.split(LINE_SEPARATOR);

        for (String tempShadow : tempShadows) {
            String[] fields = tempShadow.split(USERINFO_SEPARATOR);

            users.stream().filter(user -> user.username.equals(fields[0])).forEach(user -> user.password = fields[1]);
        }
    }

    private void performCracking() {
        for (User user : users) {
            for (String worstPassword : worstPasswords) {
                if (user.password.length() > 1) {
                    if (Sha512Crypt.verifyPassword(worstPassword, user.password)) {
                        // System.out.println("Found a password for " + user.username + " : " + worstPassword);
                        user.crackedPassword = worstPassword;
                        break;
                    }
                }
            }
        }
    }

    private void displayResults() throws IOException {
        System.out.println("===== PASSWORD CRACKER RESULTS =====");
        String all = "";
        for (User user : users) {
            if (!user.crackedPassword.isEmpty()) {
                String result = "User ID: " + user.userId + " / Username: " + user.username + " / Password: " + user.crackedPassword;
                System.out.println(result);
                all += result + LINE_SEPARATOR;
            }
        }
        System.out.println("=====      END OF RESULTS      =====");

        FileUtils.writeStringToFile(fileOutput, all, Charsets.UTF_8, false);
        // the false means don't append to current file
    }

    private class User {
        private String username = "";
        private int userId = -1;
        private String password = "";
        private String crackedPassword = "";
    }

}
