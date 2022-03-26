package io.amit.bouncy_castle_demo.from_google;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
public class ReadPrivateKeyP12 {
    public static void main(String[] args) {
        try {
            final String base_loc = "D:\\amit-working-directory\\IdeaProjects\\bouncy_castle_demo\\src\\main\\java\\io\\amit\\bouncy_castle_demo\\";

            String filePath = "D:/amit_public_cert.cer";
            filePath = base_loc + "Baeldung.p12";

            KeyStore p12 = KeyStore.getInstance("pkcs12");

            // getPassword returns the password of the key / file. The password should not be hard coded.
            p12.load(new FileInputStream(filePath),
                    "password".toCharArray());

            // the key is ready to be used !
            Key key = p12.getKey("baeldung", "password".toCharArray());

            System.out.println("private key: "+key);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
