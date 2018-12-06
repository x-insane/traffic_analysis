package com.xinsane.traffic_analysis.helper;

import java.util.Random;

public class RandomStringHelper {
    private static final Random random = new Random(System.currentTimeMillis());

    public static String randomString(int length) {
        String source = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder builder =new StringBuilder();
        for(int i = 0; i < length; i++) {
            int number = random.nextInt(source.length());
            builder.append(source.charAt(number));
        }
        return builder.toString();
    }

}
