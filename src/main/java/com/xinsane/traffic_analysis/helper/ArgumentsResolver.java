package com.xinsane.traffic_analysis.helper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ArgumentsResolver {
    private static final Logger logger = LoggerFactory.getLogger(ArgumentsResolver.class);
    
    public static Result resolve(String[] args) {
        Result result = new Result();
        for (int i = 0; i < args.length; ++i) {
            String arg = args[i];
            if (arg.startsWith("-")) {
                String key = arg.substring(1);
                if (++i < args.length) {
                    String value = args[i];
                    if (value.startsWith("-")) {
                        logger.error("invalid value " + value + " for flag " + key + ".");
                        System.exit(-1);
                    } else
                        result.flags.put(key, value);
                } else {
                    logger.error("no value for flag " + key + ".");
                    System.exit(-1);
                }
            } else
                result.args.add(arg);
        }
        return result;
    }

    public static class Result {
        public final Map<String, String> flags = new HashMap<>();
        public final List<String> args = new ArrayList<>();
    }
}
