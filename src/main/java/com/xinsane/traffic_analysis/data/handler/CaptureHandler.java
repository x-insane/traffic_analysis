package com.xinsane.traffic_analysis.data.handler;

import com.google.gson.Gson;
import com.xinsane.traffic_analysis.Application;
import com.xinsane.traffic_analysis.data.CaptureInformation;
import com.xinsane.traffic_analysis.data.dumper.DefaultDumper;
import com.xinsane.traffic_analysis.data.dumper.Dumper;
import com.xinsane.traffic_analysis.data.exception.UnknownPacketException;
import com.xinsane.traffic_analysis.data.packet.SFrame;
import com.xinsane.traffic_analysis.helper.AESCryptHelper;
import com.xinsane.traffic_analysis.websocket.WSHandler;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.*;
import java.util.stream.Collectors;

public class CaptureHandler implements Runnable, SourceHandler, Dumper.HandlerInformation {
    private static final Logger logger = LoggerFactory.getLogger(CaptureHandler.class);

    // 单例模式
    private CaptureHandler() { init(); }
    private static CaptureHandler instance = new CaptureHandler();
    public static CaptureHandler getInstance() {
        return instance;
    }

    // runner thread
    private Thread thread = null;
    // Bind Websocket Sessions
    private List<WSHandler> websockets = new ArrayList<>();
    // Capture Status
    private Status status = Status.NONE;
    // Network Interface
    private PcapNetworkInterface nif;
    private PcapHandle handle;
    private String filter = null;
    // Packet Dumper
    private String dumperName = null;
    private Dumper dumper = null;
    // 捕获详情
    private CaptureInformation information = null;

    public void setNetworkInterfaceAndCapture(PcapNetworkInterface nif, String filter) {
        this.nif = nif;
        this.filter = filter;
        startCapture();
    }

    private void handlePacket(Packet packet) {
        // 解析
        SFrame frame;
        try {
            frame = new SFrame();
            frame.load(packet);
        } catch (UnknownPacketException e) {
            logger.debug("handler an unknown packet.");
            logger.debug(new Gson().toJson(packet));
            frame = null;
        }

        // 类型统计
        information.count();
        if (packet.contains(IpPacket.class)) {
            information.count("ip");
            if (packet.contains(IpV4Packet.class))
                information.count("ipv4");
            else if (packet.contains(IpV6Packet.class))
                information.count("ipv6");
            if (packet.contains(TcpPacket.class))
                information.count("tcp");
            else if (packet.contains(UdpPacket.class))
                information.count("udp");
            if (packet.contains(IcmpV4CommonPacket.class)) {
                information.count("icmp");
                information.count("icmpv4");
            } else if (packet.contains(IcmpV6CommonPacket.class)) {
                information.count("icmp");
                information.count("icmpv6");
            }
        }
        else if (packet.contains(ArpPacket.class))
            information.count("arp");

        // WebSocket
        if (frame != null) {
            String encryptedFrame = AESCryptHelper.encrypt(new Gson().toJson(frame));
            for (WSHandler websocket : websockets) {
                if (websocket.isOpen())
                    websocket.sendPacket(encryptedFrame);
            }
        }

        // 文件
        dumper.addPacket(packet);
    }

    @Override
    public void run() {
        try {
            PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
            handle = nif.openLive(65536, mode, 10);
            final List<InetAddress> interface_ips = nif.getAddresses().stream()
                    .map(PcapAddress::getAddress)
                    .collect(Collectors.toList());
            if (filter != null)
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            handle.loop(-1, (PacketListener) packet -> {
                IpPacket ipPacket = packet.get(IpPacket.class);
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                if (ipPacket != null && tcpPacket != null) {
                    InetAddress src_address = ipPacket.getHeader().getSrcAddr();
                    int src_port = tcpPacket.getHeader().getSrcPort().value();
                    InetAddress dst_address = ipPacket.getHeader().getDstAddr();
                    int dst_port = tcpPacket.getHeader().getDstPort().value();
                    // 过滤本应用发出的报文
                    if (interface_ips.contains(src_address) &&
                            (src_port == Application.http_port || src_port == Application.https_port))
                        return;
                    // 过滤本应用收到的报文
                    if (interface_ips.contains(dst_address) &&
                            (dst_port == Application.http_port || dst_port == Application.https_port))
                        return;
                }
                handlePacket(packet);
            });
        } catch (InterruptedException | NotOpenException | PcapNativeException e) {
            e.printStackTrace();
            handle = null;
            stopCapture();
            // 向所有在线websocket发送错误消息
            if (!(e instanceof InterruptedException))
                sendErrorToAll(AESCryptHelper.encrypt(e.getMessage()));
        } finally {
            // 向所有在线websocket发送中断消息
            sendStatusToAll();
        }
    }

    private void startCapture() {
        if (thread == null) {
            initData();
            thread = new Thread(this);
            thread.setDaemon(true); // 主线程结束后退出
            thread.start();
            information.start();
            status = Status.RUNNING;
        }
        // 向所有在线websocket发送开始捕获消息
        sendStatusToAll();
    }

    public void stopCapture() {
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }
        if (dumper != null)
            dumper.close();
        information.stop();
        status = Status.NONE;
        thread = null;
    }

    /**
     * 群发已加密的错误信息
     * @param error 已加密的错误信息
     */
    private void sendErrorToAll(String error) {
        for (WSHandler websocket : websockets) {
            if (websocket.isOpen())
                websocket.sendError(error);
        }
    }

    /**
     * 群发已加密的捕获状态信息
     */
    private void sendStatusToAll() {
        String wrappedStatus = wrapCaptureStatus();
        for (WSHandler websocket : websockets) {
            if (websocket.isOpen())
                websocket.sendCaptureStatus(wrappedStatus);
        }
    }

    private void init() {
        Runtime.getRuntime().addShutdownHook(new Thread(this::closeDumper));
    }

    private void initData() {
        dumperName = UUID.randomUUID().toString().substring(0, 6);
        dumper = new DefaultDumper(this);
        information = new CaptureInformation();
    }

    private void closeDumper() {
        if (dumper != null) {
            dumper.close();
            dumper.clearTmpFiles();
            dumper = null;
        }
    }

    /**
     * 包装已被加密的状态信息
     */
    public String wrapCaptureStatus() {
        Map<String, Object> map = new HashMap<>();
        map.put("running", status == Status.RUNNING);
        map.put("interface", WSHandler.loadInterfaceFromNif(nif));
        map.put("filter", filter);
        return AESCryptHelper.encrypt(new Gson().toJson(map));
    }

    @Override
    public void bindWebSocketHandler(WSHandler handler) {
        websockets.add(handler);
    }

    @Override
    public CaptureInformation getInformation() {
        return information;
    }

    @Override
    public PcapHandle getHandle() {
        return handle;
    }

    @Override
    public String getDumperName() {
        return dumperName;
    }

    public Status getStatus() {
        return status;
    }

    public String getFilter() {
        return filter;
    }

    public enum Status {
        NONE, // 未选择网卡
        RUNNING, // 正在捕获
        STOP // 已选择网卡，未开始捕获
    }
}
