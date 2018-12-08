package com.xinsane.traffic_analysis.helper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Helper {
    private static final Logger logger = LoggerFactory.getLogger(MD5Helper.class);

    public static String md5(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(text.getBytes(StandardCharsets.UTF_8));
            String result = new BigInteger(1, md.digest()).toString(16);
            StringBuilder builder = new StringBuilder(32);
            for (int i = 0; i < 32 - result.length(); ++i)
                builder.append('0'); // MD5值补足位数
            builder.append(result);
            return builder.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            logger.error(e.getMessage());
        }
        return "";
    }
}
