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
        h.raw = header.getRawData();
        h.length = header.getIhl();
        h.typeOfService = header.getTos().value();
        h.totalLength = header.getTotalLength();
        h.identification = header.getIdentification();
        h.flag = new Header.Flag();
        h.flag.reservedFlag = header.getReservedFlag();
        h.flag.dontFragmentFlag = header.getDontFragmentFlag();
        h.flag.moreFragmentFlag = header.getMoreFragmentFlag();
        h.fragmentOffset = header.getFragmentOffset();
        h.ttl = header.getTtl();
        h.protocol = header.getProtocol().value();
        h.headerChecksum = header.getHeaderChecksum();
        h.src = header.getSrcAddr().toString();
        h.dst = header.getDstAddr().toString();
        h.options = header.getOptions().stream()
                .map(IpV4Packet.IpV4Option::getRawData)
                .collect(Collectors.toList());
        h.padding = header.getPadding();
        this.header = h;
    }

    public static class Header {
        private byte[] raw;
        private byte version = 4;
        private byte length;
        private byte typeOfService;
        private short totalLength;
        private short identification;
        private Flag flag;
        private short fragmentOffset;
        private byte ttl;
        private byte protocol;
        private short headerChecksum;
        private String src;
        private String dst;
        private List<byte[]> options;
        private byte[] padding;

        public static class Flag {
            private boolean reservedFlag;
            private boolean dontFragmentFlag;
            private boolean moreFragmentFlag;

            public boolean isReservedFlag() {
                return reservedFlag;
            }

            public boolean isDontFragmentFlag() {
                return dontFragmentFlag;
            }

            public boolean isMoreFragmentFlag() {
                return moreFragmentFlag;
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

        public short getIdentification() {
            return identification;
        }

        public Flag getFlag() {
            return flag;
        }

        public short getFragmentOffset() {
            return fragmentOffset;
        }

        public byte getTtl() {
            return ttl;
        }

        public byte getProtocol() {
            return protocol;
        }

        public short getHeaderChecksum() {
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
