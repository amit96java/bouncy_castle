package io.amit.bouncy_castle_demo.michel_schudel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashingDemo {

    public static void hashText(String s) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] input = s.getBytes();
        byte[] digest = messageDigest.digest(input);
        System.out.println("Input: "+s);
        System.out.println("Digest: "+digest);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InterruptedException {
        hashText("amit");
        Thread.sleep(100);
        hashText("amit");
        hashText("i live in kanpur");
    }
}
