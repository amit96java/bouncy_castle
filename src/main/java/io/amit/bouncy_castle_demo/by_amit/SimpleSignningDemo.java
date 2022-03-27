package io.amit.bouncy_castle_demo.by_amit;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class SimpleSignningDemo {
    final static String base_loc = "D:\\amit-working-directory\\IdeaProjects\\bouncy_castle_demo\\src\\main\\java\\io\\amit\\bouncy_castle_demo\\";


    public static void main(String[] args) throws GeneralSecurityException, FileNotFoundException {
        PublicKey publicKey = getPublicKeyFromCertificat(base_loc + "Baeldung.cer");
        System.out.println("public key from certificate "+publicKey);
        testAsymmetricSigningWithSignatureClasses();
    }

    public static void testAsymmetricSigningWithSignatureClasses() throws GeneralSecurityException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);

        KeyPair keyPair = kpGen.generateKeyPair();

        System.out.println("private Key: " + keyPair.getPrivate().getEncoded());
        System.out.println("public Key: " + keyPair.getPublic().getEncoded());

        String data = "I believe in God";

        Signature signatureAlgorithm = Signature.getInstance("SHA256WithRSA");
        signatureAlgorithm.initSign(keyPair.getPrivate());

        //signature with data (this data we will match to verify)
        signatureAlgorithm.update(data.getBytes());

        byte[] signature = signatureAlgorithm.sign();
        System.out.println("signature: " + signature);

        //verification on the other end
        Signature verificationAlgorithm = Signature.getInstance("SHA256WithRSA");
        //if we are using certificate than we will get this public key from certificate
        verificationAlgorithm.initVerify(keyPair.getPublic());
        verificationAlgorithm.update(data.getBytes());
        //verify data
        boolean matches = verificationAlgorithm.verify(signature);
        System.out.println("signature matches " + matches);
    }

    public static PublicKey getPublicKeyFromCertificat(String certificatePath) throws FileNotFoundException, CertificateException {
        FileInputStream fin = new FileInputStream(certificatePath);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
        PublicKey pk = certificate.getPublicKey();
        return pk;
    }
}
