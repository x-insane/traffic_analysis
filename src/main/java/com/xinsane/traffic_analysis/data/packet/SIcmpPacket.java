package com.xinsane.traffic_analysis.data.packet;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.Packet;

public abstract class SIcmpPacket {
    private Header header;

    void load(Packet packet) {
        loadHeader(packet.getHeader());
    }

    private void loadHeader(Packet.Header header) {
        Header h = new Header();
        // h.raw = header.getRawData();
        if (header instanceof IcmpV4CommonPacket.IcmpV4CommonHeader) {
            IcmpV4CommonPacket.IcmpV4CommonHeader header4 = (IcmpV4CommonPacket.IcmpV4CommonHeader) header;
            h.type = header4.getType().value() & 0xff;
            h.typeName = header4.getType().name();
            h.code = header4.getCode().value();
            h.codeName = header4.getCode().name();
            h.checksum = header4.getChecksum() & 0xffff;
        } else {
            IcmpV6CommonPacket.IcmpV6CommonHeader header6 = (IcmpV6CommonPacket.IcmpV6CommonHeader) header;
            h.type = header6.getType().value() & 0xff;
            h.typeName = header6.getType().name();
            h.code = header6.getCode().value();
            h.codeName = header6.getCode().name();
            h.checksum = header6.getChecksum() & 0xffff;
        }
        this.header = h;
    }

    public static class Header {
        private byte[] raw;
        private int type;
        private String typeName;
        private byte code;
        private String codeName;
        private int checksum;

        public byte[] getRaw() {
            return raw;
        }

        public int getType() {
            return type;
        }

        public String getTypeName() {
            return typeName;
        }

        public byte getCode() {
            return code;
        }

        public String getCodeName() {
            return codeName;
        }

        public int getChecksum() {
            return checksum;
        }
    }

    public Header getHeader() {
        return header;
    }
}
