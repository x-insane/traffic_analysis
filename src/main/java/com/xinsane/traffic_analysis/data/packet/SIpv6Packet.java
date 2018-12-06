package com.xinsane.traffic_analysis.data.packet;

import org.pcap4j.packet.IpV6Packet;

public class SIpv6Packet extends SIpPacket {
    private Header header;

    public void load(IpV6Packet packet) {
        loadHeader(packet.getHeader());
        super.load(packet);
    }

    private void loadHeader(IpV6Packet.IpV6Header header) {
        Header h = new Header();
        // h.raw = header.getRawData();
        h.trafficClass = header.getTrafficClass().value();
        h.flowLabel = header.getFlowLabel().value();
        h.payloadLength = header.getPayloadLength();
        h.nextHeader = header.getNextHeader().value();
        h.nextHeaderName = header.getNextHeader().name();
        h.hopLimit = header.getHopLimitAsInt();
        h.src = header.getSrcAddr().toString().substring(1);
        h.dst = header.getDstAddr().toString().substring(1);
        this.header = h;
    }

    public static class Header {
        private byte[] raw;
        private byte version = 6;
        private byte trafficClass;
        private int flowLabel;
        private short payloadLength;
        private byte nextHeader;
        private String nextHeaderName;
        private int hopLimit;
        private String src;
        private String dst;

        public byte[] getRaw() {
            return raw;
        }

        public byte getVersion() {
            return version;
        }

        public byte getTrafficClass() {
            return trafficClass;
        }

        public int getFlowLabel() {
            return flowLabel;
        }

        public short getPayloadLength() {
            return payloadLength;
        }

        public byte getNextHeader() {
            return nextHeader;
        }

        public String getNextHeaderName() {
            return nextHeaderName;
        }

        public int getHopLimit() {
            return hopLimit;
        }

        public String getSrc() {
            return src;
        }

        public String getDst() {
            return dst;
        }
    }

    public Header getHeader() {
        return header;
    }
}
