package io.amit.bouncy_castle_demo.michel_schudel.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;

public class SymmetricEncryptionCBCDemo {
    public static void testSymmetricEncryption() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(192);
        Key key = generator.generateKey();
        System.out.println("Key: "+key.getEncoded());

        byte[] input = "text".repeat(16).getBytes();
        System.out.println("Input: "+input);

        //with cipher block chaining
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] random = new byte[16];
        secureRandom.nextBytes(random);
        IvParameterSpec ivSpec = new IvParameterSpec(random);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);



        byte[] encryptedOutput = cipher.doFinal(input);
        System.out.println("Cipher Test: "+encryptedOutput);

        //decrypt on other end
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptOutput = cipher.doFinal(encryptedOutput);

        System.out.println("Decrypt Output : "+decryptOutput);
        String s = new String(decryptOutput, StandardCharsets.UTF_8);
        System.out.println("final data "+s);



    }
}
