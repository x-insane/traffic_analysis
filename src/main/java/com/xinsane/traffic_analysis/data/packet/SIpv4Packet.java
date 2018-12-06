package com.xinsane.traffic_analysis.data.packet;

import org.pcap4j.packet.*;

import java.util.List;
import java.util.stream.Collectors;

public class SIpv4Packet extends SIpPacket {
    private Header header;

    public void load(IpV4Packet packet) {
        loadHeader(packet.getHeader());
        super.load(packet);
    }

    private void loadHeader(IpV4Packet.IpV4Header header) {
        Header h = new Header();
        // h.raw = header.getRawData();
        h.length = header.getIhl();
        h.typeOfService = header.getTos().value();
        h.totalLength = header.getTotalLength();
        h.identification = header.getIdentificationAsInt();
        h.flag = new Header.Flag();
        h.flag.reservedFlag = header.getReservedFlag();
        h.flag.dontFragmentFlag = header.getDontFragmentFlag();
        h.flag.moreFragmentFlag = header.getMoreFragmentFlag();
        h.flag.fragmentOffset = header.getFragmentOffset();
        h.ttl = header.getTtlAsInt();
        h.protocol = header.getProtocol().value();
        h.protocolName = header.getProtocol().name();
        h.headerChecksum = header.getHeaderChecksum() & 0xffff;
        h.src = header.getSrcAddr().toString().substring(1);
        h.dst = header.getDstAddr().toString().substring(1);
//        h.options = header.getOptions().stream()
//                .map(IpV4Packet.IpV4Option::getRawData)
//                .collect(Collectors.toList());
//        h.padding = header.getPadding();
        this.header = h;
    }

    public static class Header {
        private byte[] raw;
        private byte version = 4;
        private byte length;
        private byte typeOfService;
        private short totalLength;
        private int identification;
        private Flag flag;
        private int ttl;
        private byte protocol;
        private String protocolName;
        private int headerChecksum;
        private String src;
        private String dst;
        private List<byte[]> options;
        private byte[] padding;

        public static class Flag {
            private boolean reservedFlag;
            private boolean dontFragmentFlag;
            private boolean moreFragmentFlag;
            private short fragmentOffset;

            public boolean isReservedFlag() {
                return reservedFlag;
            }

            public boolean isDontFragmentFlag() {
                return dontFragmentFlag;
            }

            public boolean isMoreFragmentFlag() {
                return moreFragmentFlag;
            }

            public short getFragmentOffset() {
                return fragmentOffset;
            }
        }

        public byte[] getRaw() {
            return raw;
        }

        public byte getVersion() {
            return version;
        }

        public byte getLength() {
            return length;
        }

        public byte getTypeOfService() {
            return typeOfService;
        }

        public short getTotalLength() {
            return totalLength;
        }

        public int getIdentification() {
            return identification;
        }

        public Flag getFlag() {
            return flag;
        }

        public int getTtl() {
            return ttl;
        }

        public byte getProtocol() {
            return protocol;
        }

        public String getProtocolName() {
            return protocolName;
        }

        public int getHeaderChecksum() {
            return headerChecksum;
        }

        public String getSrc() {
            return src;
        }

        public String getDst() {
            return dst;
        }

        public List<byte[]> getOptions() {
            return options;
        }

        public byte[] getPadding() {
            return padding;
        }
    }

    public Header getHeader() {
        return header;
    }
}
