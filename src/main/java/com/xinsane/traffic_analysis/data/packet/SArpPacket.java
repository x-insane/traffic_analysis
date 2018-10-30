package com.xinsane.traffic_analysis.data.packet;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

public class SArpPacket {
    private String type;
    private Header header;
    private SRawPacket raw;

    public void load(ArpPacket packet) {
        loadHeader(packet.getHeader());
        Packet payload = packet.getPayload();
        if (payload != null) {
            type = "raw";
            raw = new SRawPacket();
            raw.load(payload);
        }
    }

    private void loadHeader(ArpPacket.ArpHeader header) {
        Header h = new Header();
        h.raw = header.getRawData();
        h.hardwareType = header.getHardwareType().value();
        h.protocolType = header.getProtocolType().value();
        h.hardwareAddressLength = header.getHardwareAddrLength();
        h.protocolAddressLength = header.getProtocolAddrLength();
        h.operation = header.getOperation().value();
        h.srcHardware = header.getSrcHardwareAddr().toString();
        h.srcProtocol = header.getSrcProtocolAddr().toString();
        h.dstHardware = header.getDstHardwareAddr().toString();
        h.dstProtocol = header.getDstProtocolAddr().toString();
        this.header = h;
    }

    public static class Header {
        private byte[] raw;
        private short hardwareType;
        private short protocolType;
        private byte hardwareAddressLength;
        private byte protocolAddressLength;
        private short operation;
        private String srcHardware;
        private String srcProtocol;
        private String dstHardware;
        private String dstProtocol;

        public byte[] getRaw() {
            return raw;
        }

        public short getHardwareType() {
            return hardwareType;
        }

        public short getProtocolType() {
            return protocolType;
        }

        public byte getHardwareAddressLength() {
            return hardwareAddressLength;
        }

        public byte getProtocolAddressLength() {
            return protocolAddressLength;
        }

        public short getOperation() {
            return operation;
        }

        public String getSrcHardware() {
            return srcHardware;
        }

        public String getSrcProtocol() {
            return srcProtocol;
        }

        public String getDstHardware() {
            return dstHardware;
        }

        public String getDstProtocol() {
            return dstProtocol;
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
