package com.xinsane.traffic_analysis.data.packet;

import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.Packet;

public class SIcmpV6Packet extends SIcmpPacket {
    private String type;
    private SRawPacket raw;

    public void load(IcmpV6CommonPacket packet) {
        super.load(packet);
        Packet payload = packet.getPayload();
        if (payload != null) {
            type = "raw";
            raw = new SRawPacket();
            raw.load(payload);
        }
    }

    public String getType() {
        return type;
    }

    public SRawPacket getRaw() {
        return raw;
    }
}
