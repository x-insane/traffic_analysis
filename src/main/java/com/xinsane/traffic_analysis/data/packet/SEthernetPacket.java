package com.xinsane.traffic_analysis.data.packet;

import org.pcap4j.packet.*;

public class SEthernetPacket {
    private String type;
    private Header header;
    private SIpv4Packet ipv4;
    private SIpv6Packet ipv6;
    private SArpPacket arp;
    private SRawPacket raw;

    public void load(EthernetPacket packet) {
        loadHeader(packet.getHeader());
        Packet payload = packet.getPayload();
        if (payload instanceof IpV4Packet) {
            type = "ipv4";
            IpV4Packet ipV4Packet = (IpV4Packet) payload;
            ipv4 = new SIpv4Packet();
            ipv4.load(ipV4Packet);
        } else if (payload instanceof IpV6Packet) {
            type = "ipv6";
            IpV6Packet ipV6Packet = (IpV6Packet) payload;
            ipv6 = new SIpv6Packet();
            ipv6.load(ipV6Packet);
        } else if (payload instanceof ArpPacket) {
            type = "arp";
            ArpPacket arpPacket = (ArpPacket) payload;
            arp = new SArpPacket();
            arp.load(arpPacket);
        } else {
            if (payload != null) {
                type = "raw";
                raw = new SRawPacket();
                raw.load(payload);
            }
        }
    }

    private void loadHeader(EthernetPacket.EthernetHeader header) {
        Header h = new Header();
        // h.raw = header.getRawData();
        h.type = header.getType().value();
        h.typeName = header.getType().name();
        h.src = header.getSrcAddr().toString();
        h.dst = header.getDstAddr().toString();
        this.header = h;
    }

    public static class Header {
        private byte[] raw;
        private short type;
        private String typeName;
        private String src;
        private String dst;

        public byte[] getRaw() {
            return raw;
        }

        public short getType() {
            return type;
        }

        public String getTypeName() {
            return typeName;
        }

        public String getSrc() {
            return src;
        }

        public String getDst() {
            return dst;
        }
    }

    public String getType() {
        return type;
    }

    public Header getHeader() {
        return header;
    }

    public SIpv4Packet getIpv4() {
        return ipv4;
    }

    public SIpv6Packet getIpv6() {
        return ipv6;
    }

    public SArpPacket getArp() {
        return arp;
    }

    public SRawPacket getRaw() {
        return raw;
    }
}
