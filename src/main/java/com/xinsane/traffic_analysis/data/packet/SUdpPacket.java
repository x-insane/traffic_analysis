package com.xinsane.traffic_analysis.data.packet;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

public class SUdpPacket {
    private String type;
    private Header header;
    private SRawPacket raw;

    public void load(UdpPacket packet) {
        loadHeader(packet.getHeader());
        Packet payload = packet.getPayload();
        if (payload != null) {
            type = "raw";
            raw = new SRawPacket();
            raw.load(payload);
        }
    }

    private void loadHeader(UdpPacket.UdpHeader header) {
        Header h = new Header();
        // h.raw = header.getRawData();
        h.srcPort = header.getSrcPort().value() & 0xffff;
        h.srcPortName = header.getSrcPort().name();
        h.dstPort = header.getDstPort().value() & 0xffff;
        h.dstPortName = header.getDstPort().name();
        h.length = header.getLength();
        h.checksum = header.getChecksum();
        this.header = h;
    }

    public static class Header {
        private byte[] raw;
        private int srcPort;
        private String srcPortName;
        private int dstPort;
        private String dstPortName;
        private short length;
        private short checksum;

        public byte[] getRaw() {
            return raw;
        }

        public int getSrcPort() {
            return srcPort;
        }

        public String getSrcPortName() {
            return srcPortName;
        }

        public int getDstPort() {
            return dstPort;
        }

        public String getDstPortName() {
            return dstPortName;
        }

        public short getLength() {
            return length;
        }

        public short getChecksum() {
            return checksum;
        }
    }

    public String getType() {
        return type;
    }

    public Header getHeader() {
        return header;
    }

    public SRawPacket getRaw() {
        return raw;
    }
}
