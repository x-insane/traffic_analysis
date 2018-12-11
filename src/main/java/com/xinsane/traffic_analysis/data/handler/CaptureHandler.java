package com.xinsane.traffic_analysis.data.handler;

import com.google.gson.Gson;
import com.xinsane.traffic_analysis.Application;
import com.xinsane.traffic_analysis.data.CaptureInformation;
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
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

public class CaptureHandler implements Runnable, SourceHandler {
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
    // 捕获结果输出
    private PcapDumper dumper = null;
    private String dumperName = null;
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
        information.count(packet);

        // WebSocket
        if (frame != null) {
            String encryptedFrame = AESCryptHelper.encrypt(new Gson().toJson(frame));
            for (WSHandler websocket : websockets) {
                if (websocket.isOpen())
                    websocket.sendPacket(encryptedFrame);
            }
        }

        // 保存为文件
        try {
            if (dumper != null)
                dumper.dump(packet);
        } catch (NotOpenException e) {
            e.printStackTrace();
            logger.error(e.getMessage());
        }
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
            // 打开输出文件
            dumperName = new SimpleDateFormat("yyyyMMddHHmmssSSS")
                    .format(System.currentTimeMillis()) + ".pcap";
            String filename = Application.dumper_dir + dumperName;
            try {
                dumper = handle.dumpOpen(filename);
            } catch (PcapNativeException | NotOpenException e) {
                e.printStackTrace();
                logger.error(e.getMessage());
            }
            // 开始循环获取报文
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
            // 开始记录统计信息
            information = new CaptureInformation();
            information.start();
            // 启动线程
            thread = new Thread(this);
            thread.setDaemon(true); // 主线程结束后退出
            thread.start();
            // 设置运行状态
            status = Status.RUNNING;
        }
        // 向所有在线websocket发送开始捕获消息
        sendStatusToAll();
    }

    public void stopCapture() {
        // 停止捕获
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }
        // 关闭输出文件
        if (dumper != null)
            dumper.close();
        // 结束统计信息
        information.stop();
        // 清理线程
        thread = null;
        // 设置运行状态
        status = Status.NONE;
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
            if (websocket.isOpen()) {
                websocket.sendCaptureStatus(wrappedStatus);
                if (status == Status.RUNNING)
                    websocket.sendInfo(AESCryptHelper.encrypt("已开始捕获"));
                else {
                    websocket.sendInfo(AESCryptHelper.encrypt("已停止捕获，已保存为" +
                            dumperName + "，请在文件管理中查看"));
                }
            }
        }
    }

    private void init() {
        Runtime.getRuntime().addShutdownHook(new Thread(this::closeDumper));
    }

    private void closeDumper() {
        if (dumper != null) {
            dumper.close();
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

    public Status getStatus() {
        return status;
    }

    public String getFilter() {
        return filter;
    }

    String getDumperName() {
        if (status == Status.RUNNING)
            return dumperName;
        return null;
    }

    public enum Status {
        NONE, // 未选择网卡
        RUNNING, // 正在捕获
        STOP // 已选择网卡，未开始捕获
    }
}
