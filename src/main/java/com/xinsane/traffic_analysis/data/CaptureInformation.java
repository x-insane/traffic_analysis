package com.xinsane.traffic_analysis.data;

import java.util.HashMap;
import java.util.Map;

public class CaptureInformation {
    private long startTime = 0;
    private long endTime = 0;
    private int totalCount = 0;
    private Map<String, Integer> statistics = new HashMap<>();

    public void count() {
        totalCount ++;
    }

    public void count(String type) {
        if (statistics.containsKey(type))
            statistics.put(type, statistics.get(type) + 1);
        else
            statistics.put(type, 1);
    }

    public void start() {
        startTime = System.currentTimeMillis();
    }

    public void stop() {
        endTime = System.currentTimeMillis();
    }

    public long getStartTime() {
        return startTime;
    }

    public long getEndTime() {
        return endTime;
    }

    public int getTotalCount() {
        return totalCount;
    }

    public Map<String, Integer> getStatistics() {
        return statistics;
    }
}
