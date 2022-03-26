package io.amit.bouncy_castle_demo.michel_schudel.asymmetric;

import javax.crypto.KeyGenerator;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class SimpleSignningDemo {

    public static void main(String[] args) throws GeneralSecurityException {
        testAsymmetricSigningWithSignatureClasses();
    }
    public static void testAsymmetricSigningWithSignatureClasses() throws GeneralSecurityException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);

        KeyPair keyPair = kpGen.generateKeyPair();

        System.out.println("private Key: "+keyPair.getPrivate().getEncoded());
        System.out.println("public Key: "+keyPair.getPublic().getEncoded());

        String data = "I believe in God";

        Signature signatureAlgorithm = Signature.getInstance("SHA256WithRSA");
        signatureAlgorithm.initSign(keyPair.getPrivate());

        //signature with data (this data we will match to verify)
        signatureAlgorithm.update(data.getBytes());

        byte[] signature = signatureAlgorithm.sign();
        System.out.println("signature: "+signature);

        //verification on the other end
        Signature verificationAlgorithm = Signature.getInstance("SHA256WithRSA");
        //if we are using certificate than we will get this public key from certificate
        verificationAlgorithm.initVerify(keyPair.getPublic());
        verificationAlgorithm.update(data.getBytes());
        //verify data
        boolean matches = verificationAlgorithm.verify(signature);
        System.out.println("signature matches "+matches);
    }
}
