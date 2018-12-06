package com.xinsane.traffic_analysis.helper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESCryptHelper {
    private static final Logger logger = LoggerFactory.getLogger(AESCryptHelper.class);
    public final static SecretKey key;

    static {
        KeyGenerator generator = null;
        try {
            generator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error("can not generate key: " + e.getMessage());
            System.exit(-1);
        }
        generator.init(256);
        key = generator.generateKey();
    }

    public static String encrypt(String text) {
        if (text == null || text.isEmpty())
            return "";
        try {
            Cipher cipher = getCipher(Cipher.ENCRYPT_MODE);
            byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
            byte[] result = cipher.doFinal(bytes);
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getMessage());
        }
        return null;
    }

    public static String decrypt(String cipherText) {
        if (cipherText == null || cipherText.isEmpty())
            return "";
        try {
            Cipher cipher = getCipher(Cipher.DECRYPT_MODE);
            byte[] bytes = Base64.getDecoder().decode(cipherText);
            byte[] result = cipher.doFinal(bytes);
            return new String(result, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            logger.error(e.getMessage());
        }
        return null;
    }

    private static Cipher getCipher(int mode) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] keyRaw = key.getEncoded();
        byte[] iv = new byte[keyRaw.length/2];
        System.arraycopy(keyRaw, 0, iv, 0, iv.length);
        cipher.init(mode, key, new IvParameterSpec(iv));
        return cipher;
    }
}
