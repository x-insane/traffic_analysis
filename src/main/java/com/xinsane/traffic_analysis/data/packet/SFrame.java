package com.xinsane.traffic_analysis.data.packet;

import com.xinsane.traffic_analysis.data.exception.UnknownPacketException;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

public class SFrame {
    private String type;
    private SEthernetPacket ethernet;

    public void load(Packet packet) {
        if (packet instanceof EthernetPacket) {
            EthernetPacket ethernetPacket = (EthernetPacket) packet;
            type = "ethernet";
            ethernet = new SEthernetPacket();
            ethernet.load(ethernetPacket);
        } else
            throw new UnknownPacketException();
    }

    public String getType() {
        return type;
    }

    public SEthernetPacket getEthernet() {
        return ethernet;
    }
}
