package io.amit.bouncy_castle_demo;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * https://www.baeldung.com/java-bouncy-castle
 */
@SpringBootApplication
public class BouncyCastleDemoApplication implements CommandLineRunner {

    final String base_loc = "D:\\amit-working-directory\\IdeaProjects\\bouncy_castle_demo\\src\\main\\java\\io\\amit\\bouncy_castle_demo\\";

    public static void main(String[] args) throws NoSuchAlgorithmException {

        SpringApplication.run(BouncyCastleDemoApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("Max Key Size for AES : " + maxKeySize);
        //mentioned the provider
        //This can also be done statically by editing the {JAVA_HOME}/jre/lib/security/java.security file, and adding this line:
        Security.addProvider(new BouncyCastleProvider());
        //mentioned the type of certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");

        //certificate file location, this certificate is used to encrypt the data
        X509Certificate certificate = (X509Certificate) certFactory
                .generateCertificate(new FileInputStream(base_loc + "Baeldung.cer"));

        //Baeldung.p12 is a keystore which contains private key
        char[] keystorePassword = "password".toCharArray();
        //password for private key
        char[] keyPassword = "password".toCharArray();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        //below file(Baeldung.p12) is a password protected keystore that contains a private key.
        /**
         * Note that a PKCS12 Keystore contains a set of private keys, each private key can have a
         * specific password, that's why we need a global password to open the Keystore, and a specific
         * one to retrieve the private key.
         */
        keyStore.load(new FileInputStream(base_loc + "Baeldung.p12"), keystorePassword);

        //The getKey() method returns the private key associated with a given alias.
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("baeldung", keyPassword);
        System.out.println("private key is " + privateKey);
        String secretMessage = "text";
        System.out.println("Original Message : " + secretMessage);
        byte[] stringToEncrypt = secretMessage.getBytes();
        //encrypt data
        byte[] encryptedData = encryptData(stringToEncrypt, certificate);
        System.out.println("Encrypted Message : " + new String(encryptedData));
        //decrypt data
        byte[] rawData = decryptData(encryptedData, privateKey);
        String decryptedMessage = new String(rawData);
        System.out.println("Decrypted Message : " + decryptedMessage);

        System.out.println("signing data...");
        byte[] signedData = signData(rawData, certificate, privateKey);
        System.out.println("verifying data..."+new String(signedData, StandardCharsets.UTF_8));
        Boolean check = verifSignData(signedData);
        System.out.println("output: "+check);

    }

    public static byte[] encryptData(byte[] data, X509Certificate encryptionCertificate)
            throws CertificateEncodingException, CMSException, IOException {

        byte[] encryptedData = null;
        if (null != data && null != encryptionCertificate) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();

            //get key from encryption certificate
            JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);

            //add key to generator
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);

            //convert data in CMS typed data
            CMSTypedData msg = new CMSProcessableByteArray(data);

            //mentioned algorithm and encryption provider
            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
                    .setProvider("BC")
                    .build();
            //generate enveloped Data
            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator
                    .generate(msg, encryptor);
            //get encoded data in byte array format.
            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    public static byte[] decryptData(byte[] encryptedData, PrivateKey decryptionKey)
            throws CMSException {

        byte[] decryptedData = null;
        if (null != encryptedData && null != decryptionKey) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

            Collection<RecipientInformation> recipients
                    = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo
                    = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient
                    = new JceKeyTransEnvelopedRecipient(decryptionKey);

            return recipientInfo.getContent(recipient);
        }
        return decryptedData;
    }

    public static byte[] signData(
            byte[] data,
            X509Certificate signingCertificate,
            PrivateKey signingKey) throws Exception {

        byte[] signedMessage = null;
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        certList.add(signingCertificate);
        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner
                = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC")
                        .build()).build(contentSigner, signingCertificate));
        cmsGenerator.addCertificates(certs);

        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        signedMessage = cms.getEncoded();
        return signedMessage;
    }


    public static boolean verifSignData(final byte[] signedData) throws CMSException, IOException, OperatorCreationException, CertificateException {
        ByteArrayInputStream bIn = new ByteArrayInputStream(signedData);
        ASN1InputStream aIn = new ASN1InputStream(bIn);
        CMSSignedData s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));
        aIn.close();
        bIn.close();
        Store certs = s.getCertificates();
        SignerInformationStore signers = s.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        SignerInformation signer = c.iterator().next();
        Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
        Iterator<X509CertificateHolder> certIt = certCollection.iterator();
        X509CertificateHolder certHolder = certIt.next();
        boolean verifResult = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
        if (!verifResult) {
            return false;
        }
        return true;
    }


}
