package com.xinsane.traffic_analysis.helper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 解析命令行参数
 * 设定参数 -option value
 * 开启特性 --feature
 */
public class ArgumentsResolver {

    public static Result resolve(String[] args) {
        return resolve(args, null, null);
    }

    /**
     * @param validOptions 合法的选项列表及其用法解释
     * @param validFeatures 合法的特性列表及其用法解释
     */
    public static Result resolve(String[] args,
                                 Map<String, String> validOptions,
                                 Map<String, String> validFeatures) {
        Result result = new Result();
        for (int i = 0; i < args.length; ++i) {
            String arg = args[i];
            if (arg.startsWith("--")) {
                String feature = arg.substring(2);
                if (validFeatures != null && !validFeatures.containsKey(feature)) {
                    die("invalid feature " + arg + ".", validOptions, validFeatures);
                    System.exit(-1);
                }
                result.features.put(feature, true);
            }
            else if (arg.startsWith("-")) {
                String key = arg.substring(1);
                if (validOptions != null && !validOptions.containsKey(key)) {
                    die("invalid options " + arg + ".", validOptions, validFeatures);
                    System.exit(-1);
                }
                if (++i < args.length) {
                    String value = args[i];
                    if (value.startsWith("-")) {
                        die("invalid value " + value + " for option " + key + ".", validOptions, validFeatures);
                        System.exit(-1);
                    } else {
                        result.options.put(key, value);
                    }
                } else {
                    die("no value for option " + key + ".", validOptions, validFeatures);
                    System.exit(-1);
                }
            } else {
                result.args.add(arg);
            }
        }
        return result;
    }

    public static void die(String message,
                           Map<String, String> validOptions,
                           Map<String, String> validFeatures) {
        System.err.println(message);
        if (validOptions != null) {
            System.err.println();
            System.err.println("valid options:");
            for (String key : validOptions.keySet()) {
                System.err.format("-%-16s %s\n", key, validOptions.get(key));
            }
        }
        if (validFeatures != null) {
            System.err.println();
            System.err.println("valid features:");
            for (String key : validFeatures.keySet()) {
                System.err.format("--%-15s %s\n", key, validFeatures.get(key));
            }
        }
        System.exit(-1);
    }

    public static class Result {
        public final Map<String, String> options = new HashMap<>();
        public final Map<String, Boolean> features = new HashMap<>();
        public final List<String> args = new ArrayList<>();
    }
}
