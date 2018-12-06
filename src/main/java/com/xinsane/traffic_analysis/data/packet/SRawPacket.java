package com.xinsane.traffic_analysis.data.packet;

import org.pcap4j.packet.Packet;

public class SRawPacket {
    public static SRawPacket from(Packet payload) {
        if (payload == null)
            return null;
        SRawPacket raw = new SRawPacket();
        raw.load(payload);
        return raw;
    }

    private int length;
    // private byte[] data;

    public void load(Packet packet) {
        // data = packet.getRawData();
        length = packet.length();
    }

    public int getLength() {
        return length;
    }

    // public byte[] getData() {
    //     return data;
    // }
}
