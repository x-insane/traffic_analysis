package com.xinsane.traffic_analysis.data.packet;

import com.xinsane.traffic_analysis.Application;
import com.xinsane.traffic_analysis.data.capture.CaptureThread;
import com.xinsane.traffic_analysis.data.exception.PacketOfSelfException;
import org.pcap4j.packet.*;

import java.net.InetAddress;
import java.util.List;

public abstract class SIpPacket {
    private String type;
    private STcpPacket tcp;
    private SUdpPacket udp;
    private SIcmpV4Packet icmpv4;
    private SIcmpV6Packet icmpv6;
    private SRawPacket raw;

    void load(IpPacket packet) {
        Packet payload = packet.getPayload();
        if (payload instanceof TcpPacket) {
            type = "tcp";
            TcpPacket tcpPacket = (TcpPacket) payload;
            tcp = new STcpPacket();
            tcp.load(tcpPacket);
            tcpCallback(packet, tcpPacket);
        } else if (payload instanceof UdpPacket) {
            type = "udp";
            UdpPacket udpPacket = (UdpPacket) payload;
            udp = new SUdpPacket();
            udp.load(udpPacket);
        } else if (payload instanceof IcmpV4CommonPacket) {
            type = "icmpv4";
            IcmpV4CommonPacket icmpV4Packet = (IcmpV4CommonPacket) payload;
            icmpv4 = new SIcmpV4Packet();
            icmpv4.load(icmpV4Packet);
        } else if (payload instanceof IcmpV6CommonPacket) {
            type = "icmpv6";
            IcmpV6CommonPacket icmpV6Packet = (IcmpV6CommonPacket) payload;
            icmpv6 = new SIcmpV6Packet();
            icmpv6.load(icmpV6Packet);
        } else {
            if (payload != null) {
                type = "raw";
                raw = new SRawPacket();
                raw.load(payload);
            }
        }
    }

    private void tcpCallback(IpPacket packet, TcpPacket tcpPacket) {
        List<InetAddress> addresses = CaptureThread.getInterface_ips();
        if (addresses != null) {
            // 过滤本应用发出的报文
            if (addresses.contains(packet.getHeader().getSrcAddr()) &&
                    tcpPacket.getHeader().getSrcPort().value() == Application.port)
                throw new PacketOfSelfException();
            // 过滤本应用收到的报文
            if (addresses.contains(packet.getHeader().getDstAddr()) &&
                    tcpPacket.getHeader().getDstPort().value() == Application.port)
                throw new PacketOfSelfException();
        }
    }

    public String getType() {
        return type;
    }

    public STcpPacket getTcp() {
        return tcp;
    }

    public SUdpPacket getUdp() {
        return udp;
    }

    public SIcmpV4Packet getIcmpv4() {
        return icmpv4;
    }

    public SIcmpV6Packet getIcmpv6() {
        return icmpv6;
    }

    public SRawPacket getRaw() {
        return raw;
    }
}
