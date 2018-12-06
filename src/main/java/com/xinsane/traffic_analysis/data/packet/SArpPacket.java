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
        raw = SRawPacket.from(payload);
        if (raw != null)
            type = "raw";
    }

    private void loadHeader(ArpPacket.ArpHeader header) {
        Header h = new Header();
        // h.raw = header.getRawData();
        h.hardwareType = header.getHardwareType().value();
        h.hardwareTypeName = header.getHardwareType().name();
        h.protocolType = header.getProtocolType().value();
        h.protocolTypeName = header.getProtocolType().name();
        h.hardwareAddressLength = header.getHardwareAddrLength();
        h.protocolAddressLength = header.getProtocolAddrLength();
        h.operation = header.getOperation().value();
        h.operationName = header.getOperation().name();
        h.srcHardware = header.getSrcHardwareAddr().toString();
        h.srcProtocol = header.getSrcProtocolAddr().toString().substring(1);
        h.dstHardware = header.getDstHardwareAddr().toString();
        h.dstProtocol = header.getDstProtocolAddr().toString().substring(1);
        this.header = h;
    }

    public static class Header {
        private byte[] raw;
        private short hardwareType;
        private String hardwareTypeName;
        private short protocolType;
        private String protocolTypeName;
        private byte hardwareAddressLength;
        private byte protocolAddressLength;
        private short operation;
        private String operationName;
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

        public String getHardwareTypeName() {
            return hardwareTypeName;
        }

        public short getProtocolType() {
            return protocolType;
        }

        public String getProtocolTypeName() {
            return protocolTypeName;
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

        public String getOperationName() {
            return operationName;
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
