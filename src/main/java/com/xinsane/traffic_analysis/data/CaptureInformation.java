package com.xinsane.traffic_analysis.data;

import org.pcap4j.packet.*;

import java.util.HashMap;
import java.util.Map;

public class CaptureInformation {
    private long startTime = 0;
    private long endTime = 0;
    private int totalCount = 0;
    private Map<String, Integer> statistics = new HashMap<>();

    private void count(String type) {
        if (statistics.containsKey(type))
            statistics.put(type, statistics.get(type) + 1);
        else
            statistics.put(type, 1);
    }
    
    public void count(Packet packet) {
        totalCount ++;
        if (packet.contains(IpPacket.class)) {
            count("ip");
            if (packet.contains(IpV4Packet.class))
                count("ipv4");
            else if (packet.contains(IpV6Packet.class))
                count("ipv6");
            if (packet.contains(TcpPacket.class))
                count("tcp");
            else if (packet.contains(UdpPacket.class))
                count("udp");
            if (packet.contains(IcmpV4CommonPacket.class)) {
                count("icmp");
                count("icmpv4");
            } else if (packet.contains(IcmpV6CommonPacket.class)) {
                count("icmp");
                count("icmpv6");
            }
        }
        else if (packet.contains(ArpPacket.class))
            count("arp");
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
    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public long getEndTime() {
        return endTime;
    }
    public void setEndTime(long endTime) {
        this.endTime = endTime;
    }

    public int getTotalCount() {
        return totalCount;
    }
    public Map<String, Integer> getStatistics() {
        return statistics;
    }
}
