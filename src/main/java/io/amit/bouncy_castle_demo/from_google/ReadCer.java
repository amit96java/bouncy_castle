package io.amit.bouncy_castle_demo.from_google;

import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ReadCer {
    public static void main(String[] args) {
        try {
            final String base_loc = "D:\\amit-working-directory\\IdeaProjects\\bouncy_castle_demo\\src\\main\\java\\io\\amit\\bouncy_castle_demo\\";

            String filePath = "D:/amit_public_cert.cer";
            filePath = base_loc + "Baeldung.cer";
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            FileInputStream is = new FileInputStream(filePath);

            X509Certificate cer = (X509Certificate) certFactory.generateCertificate(is);

            PublicKey key = cer.getPublicKey();
            System.out.println("public key "+key);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
