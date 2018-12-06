package com.xinsane.traffic_analysis.data.packet;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.List;
import java.util.stream.Collectors;

public class STcpPacket {
    private String type;
    private Header header;
    private SRawPacket raw;

    public void load(TcpPacket packet) {
        loadHeader(packet.getHeader());
        Packet payload = packet.getPayload();
        if (payload != null) {
            type = "raw";
            raw = new SRawPacket();
            raw.load(payload);
        }
    }

    private void loadHeader(TcpPacket.TcpHeader header) {
        Header h = new Header();
        // h.raw = header.getRawData();
        h.srcPort = header.getSrcPort().value() & 0xffff;
        h.srcPortName = header.getSrcPort().name();
        h.dstPort = header.getDstPort().value() & 0xffff;
        h.dstPortName = header.getDstPort().name();
        h.sequenceNumber = header.getSequenceNumberAsLong();
        h.acknowledgmentNumber = header.getAcknowledgmentNumberAsLong();
        h.dataOffset = header.getDataOffset();
        h.flag = new Header.Flag();
        h.flag.reserved = header.getReserved();
        h.flag.urg = header.getUrg();
        h.flag.ack = header.getAck();
        h.flag.psh = header.getPsh();
        h.flag.rst = header.getRst();
        h.flag.syn = header.getSyn();
        h.flag.fin = header.getFin();
        h.window = header.getWindow();
        h.checksum = header.getChecksum() & 0xffff;
        h.urgentPointer = header.getUrgentPointer();
        h.options = header.getOptions().stream()
                .map(TcpPacket.TcpOption::getRawData)
                .collect(Collectors.toList());
        h.padding = header.getPadding();
        this.header = h;
    }

    public static class Header {
        private byte[] raw;
        private int srcPort;
        private String srcPortName;
        private int dstPort;
        private String dstPortName;
        private long sequenceNumber;
        private long acknowledgmentNumber;
        private byte dataOffset;
        private Flag flag;
        private short window;
        private int checksum;
        private short urgentPointer;
        private List<byte[]> options;
        private byte[] padding;

        public static class Flag {
            private byte reserved;
            private boolean urg;
            private boolean ack;
            private boolean psh;
            private boolean rst;
            private boolean syn;
            private boolean fin;

            public byte getReserved() {
                return reserved;
            }

            public boolean isUrg() {
                return urg;
            }

            public boolean isAck() {
                return ack;
            }

            public boolean isPsh() {
                return psh;
            }

            public boolean isRst() {
                return rst;
            }

            public boolean isSyn() {
                return syn;
            }

            public boolean isFin() {
                return fin;
            }
        }

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

        public long getSequenceNumber() {
            return sequenceNumber;
        }

        public long getAcknowledgmentNumber() {
            return acknowledgmentNumber;
        }

        public byte getDataOffset() {
            return dataOffset;
        }

        public Flag getFlag() {
            return flag;
        }

        public short getWindow() {
            return window;
        }

        public int getChecksum() {
            return checksum;
        }

        public short getUrgentPointer() {
            return urgentPointer;
        }

        public List<byte[]> getOptions() {
            return options;
        }

        public byte[] getPadding() {
            return padding;
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
