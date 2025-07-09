package org.velocitynetwork.contracts;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AesGcmEncryptor {

    private static final int SALT_LENGTH = 64;
    private static final int IV_LENGTH = 16;
    private static final int TAG_LENGTH_BIT = 128;
    private static final int KEY_LENGTH_BIT = 256;
    private static final int PBKDF2_ITERATIONS = 2145;

    public static byte[] encrypt(byte[] buffer, String secret) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKey key = deriveKey(secret, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] ciphertext = cipher.doFinal(buffer);
        byte[] tag = cipher.getIV(); // tag is internally appended in GCM
        byte[] authTag = cipher.getParameters().getParameterSpec(GCMParameterSpec.class).getIV(); // not always reliable

        byte[] full = new byte[salt.length + iv.length + TAG_LENGTH_BIT / 8 + ciphertext.length];
        System.arraycopy(salt, 0, full, 0, salt.length);
        System.arraycopy(iv, 0, full, salt.length, iv.length);
        System.arraycopy(cipher.getIV(), 0, full, salt.length + iv.length, TAG_LENGTH_BIT / 8); // 16 bytes tag
        System.arraycopy(ciphertext, 0, full, salt.length + iv.length + TAG_LENGTH_BIT / 8, ciphertext.length);

        return full;
    }

    public static byte[] decrypt(byte[] data, String secret) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        byte[] tag = new byte[TAG_LENGTH_BIT / 8];
        byte[] ciphertext = new byte[data.length - salt.length - iv.length - tag.length];

        System.arraycopy(data, 0, salt, 0, salt.length);
        System.arraycopy(data, salt.length, iv, 0, iv.length);
        System.arraycopy(data, salt.length + iv.length, tag, 0, tag.length);
        System.arraycopy(data, salt.length + iv.length + tag.length, ciphertext, 0, ciphertext.length);

        SecretKey key = deriveKey(secret, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        cipher.updateAAD(tag); // Optional, depending on tagging mode

        return cipher.doFinal(ciphertext);
    }

    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BIT);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}