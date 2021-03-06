package com.xinsane.traffic_analysis.websocket;

import com.google.gson.Gson;
import com.xinsane.traffic_analysis.data.CaptureInformation;
import com.xinsane.traffic_analysis.data.handler.CaptureHandler;
import com.xinsane.traffic_analysis.data.handler.PacketFileHandler;
import com.xinsane.traffic_analysis.data.handler.SourceHandler;
import com.xinsane.traffic_analysis.helper.AESCryptHelper;
import com.xinsane.traffic_analysis.helper.MD5Helper;
import com.xinsane.traffic_analysis.helper.RandomStringHelper;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.*;
import org.eclipse.jetty.websocket.server.WebSocketHandler;
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;

@WebSocket
public class WSHandler extends WebSocketHandler {
    private static final Logger logger = LoggerFactory.getLogger(WSHandler.class);

    private Session session = null;
    private boolean proxyUser = false;
    private boolean validUser = false;
    private String verifySeed = RandomStringHelper.randomString(16);
    private SourceHandler handler = null;
    private List<PcapNetworkInterface> interfaces = null;

    public WSHandler() {
        logger.debug("websocket instance create.");
    }

    @OnWebSocketClose
    public void onClose(int statusCode, String reason) {
        logger.debug("Websocket Closed.");
        if (handler instanceof PacketFileHandler)
            ((PacketFileHandler) handler).unbindFile();
    }

    @OnWebSocketError
    public void onError(Throwable t) {
        logger.error(t.getMessage());
    }

    @OnWebSocketConnect
    public void onConnect(Session session) {
        this.session = session;
        sendVerifyHello();
    }

    @OnWebSocketMessage
    public void onMessage(String message) {
        Message msg = new Gson().fromJson(message, Message.class);
        if (msg == null)
            return;
        switch (msg.action) {
            case "hello":
                // HELLO报文：客户端（第二次握手消息）
                // - 取服务器hello消息的seed的hash作为新seed
                // - msg.data: 新seed的加密后的密文
                // - msg.extra.type: 客户端类型，只能取capture或file
                String expect = AESCryptHelper.encrypt(MD5Helper.md5(verifySeed));
                validUser = Objects.equals(expect, msg.data);
                if (!validUser)
                    logger.debug("invalid hello: " + msg.data + ", " + expect + " expected.");
                else {
                    String type = msg.extra.get("type");
                    if ("capture".equals(type)) {
                        handler = CaptureHandler.getInstance();
                        logger.debug("a valid capture user said hello.");
                    } else if ("file".equals(type)) {
                        handler = new PacketFileHandler();
                        logger.debug("a valid file user said hello.");
                    }
                    if (handler != null)
                        handler.bindWebSocketHandler(this);
                    if (session.getUpgradeRequest().getHeader("X-Forwarded-For") != null) {
                        proxyUser = true;
                        sendInfo(AESCryptHelper.encrypt("您正在使用代理访问，为避免循环流量，将不会转发报文详情"));
                    }
                }
                sendVerifyResult();
                break;
            case "ping": {
                Map<String, Object> map = new HashMap<>();
                map.put("action", "pong");
                sendString(new Gson().toJson(map));
                break;
            }
            case "command": {
                if (handler == null)
                    break;
                String text = AESCryptHelper.decrypt(msg.data);
                if (text != null && !text.isEmpty()) {
                    Command command = new Gson().fromJson(text, Command.class);
                    handleCommand(command);
                }
                break;
            }
        }
    }

    /**
     * 处理经过解密后的控制指令
     * @param command 经过解密后的控制指令
     */
    private void handleCommand(Command command) {
        if (!"statistics".equals(command.command))
            logger.debug("user command: " + command);
        switch (command.command) {
            // 捕获命令
            case "list_interfaces": {
                try {
                    this.interfaces = Pcaps.findAllDevs();
                    Map<String, Object> map = new HashMap<>();
                    map.put("action", "interfaces");
                    List<Interface> interfaces = new ArrayList<>();
                    for (PcapNetworkInterface inter : this.interfaces)
                        interfaces.add(loadInterfaceFromNif(inter));
                    map.put("interfaces", AESCryptHelper.encrypt(new Gson().toJson(interfaces)));
                    sendString(new Gson().toJson(map));
                } catch (PcapNativeException e) {
                    e.printStackTrace();
                    sendError(AESCryptHelper.encrypt(e.getMessage()));
                }
                break;
            }
            case "capture_status":
                sendCaptureStatus(CaptureHandler.getInstance().wrapCaptureStatus());
                break;
            case "start_capture": {
                if (CaptureHandler.getInstance().getStatus() == CaptureHandler.Status.RUNNING) {
                    sendCaptureStatus(CaptureHandler.getInstance().wrapCaptureStatus());
                    break;
                }
                int index = (int) (double) command.extra.get("index");
                String filter = (String) command.extra.get("filter");
                CaptureHandler.getInstance().setNetworkInterfaceAndCapture(interfaces.get(index), filter);
                break;
            }
            case "stop_capture":
                CaptureHandler.getInstance().stopCapture();
                break;
            // 通用命令
            case "statistics":
                sendStatistics();
                break;
            // 文件管理命令
            case "list_files":
                if (handler instanceof PacketFileHandler)
                    ((PacketFileHandler) handler).listFiles();
                break;
            case "delete_files": {
                if (handler instanceof PacketFileHandler) {
                    List files = (List) command.extra.get("files");
                    if (files != null)
                        ((PacketFileHandler) handler).deleteFiles(files);
                }
                break;
            }
            case "bind_file": {
                String filename = (String) command.extra.get("filename");
                String filter = (String) command.extra.get("filter");
                if (handler instanceof PacketFileHandler)
                    ((PacketFileHandler) handler).bindFile(filename, filter);
                break;
            }
            case "request_packets": {
                int start = (int) (double) command.extra.get("start");
                int number = (int) (double) command.extra.get("number");
                if (handler instanceof PacketFileHandler)
                    ((PacketFileHandler) handler).requestPackets(start, number);
                break;
            }
            case "unbind_file":
                if (handler instanceof PacketFileHandler)
                    ((PacketFileHandler) handler).unbindFile();
                break;
        }
    }

    @Override
    public void configure(WebSocketServletFactory factory) {
        factory.getPolicy().setIdleTimeout(15 * 24 * 3600 * 1000); // 即使没有数据也能存活15天
        factory.register(WSHandler.class);
    }

    public boolean isOpen() {
        return session != null && session.isOpen();
    }

    /**
     * HELLO报文：服务器端
     * 字段名明文传输，hello信息加密传输
     */
    private void sendVerifyHello() {
        String seed = String.valueOf(verifySeed);
        Map<String, Object> map = new HashMap<>();
        map.put("action", "hello");
        map.put("seed", seed); // 随机字符串
        map.put("cipher", AESCryptHelper.encrypt(seed)); // 密文，用于前端检测key是否正确
        sendString(new Gson().toJson(map));
    }

    /**
     * 通知用户是否成功验证key
     */
    private void sendVerifyResult() {
        Map<String, Object> map = new HashMap<>();
        map.put("action", "verify");
        map.put("result", validUser);
        sendString(new Gson().toJson(map));
    }

    /**
     * 发送错误信息
     * @param error 加密的错误信息
     */
    public void sendError(String error) {
        Map<String, Object> map = new HashMap<>();
        map.put("action", "error");
        map.put("error", error);
        sendString(new Gson().toJson(map));
    }

    /**
     * 发送提示消息
     * @param info 加密的提示消息
     */
    public void sendInfo(String info) {
        Map<String, Object> map = new HashMap<>();
        map.put("action", "info");
        map.put("info", info);
        sendString(new Gson().toJson(map));
    }

    /**
     * 发送统计信息
     */
    public void sendStatistics() {
        if (handler != null) {
            CaptureInformation information = handler.getInformation();
            if (information != null) {
                Map<String, Object> map = new HashMap<>();
                map.put("action", "statistics");
                map.put("statistics", AESCryptHelper.encrypt(new Gson().toJson(information)));
                map.put("time", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS")
                        .format(System.currentTimeMillis()));
                sendString(new Gson().toJson(map));
            }
        }
    }

    /**
     * 发送一个数据报文记录，报文主体需要加密
     * @param frame 经过加密的数据报文记录
     */
    public void sendPacket(String frame) {
        if (!validUser)
            return;
        // 为避免循环流量，不向使用代理的用户发送报文详情
        if (proxyUser)
            return;
        Map<String, Object> map = new HashMap<>();
        map.put("action", "packet");
        map.put("packet", frame);
        map.put("time", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date()));
        sendString(new Gson().toJson(map));
    }

    /**
     * 【仅捕获客户端】发送捕获状态信息
     * @param wrappedStatus 已加密的状态信息
     */
    public void sendCaptureStatus(String wrappedStatus) {
        Map<String, Object> map = new HashMap<>();
        map.put("action", "status");
        map.put("data", wrappedStatus);
        sendString(new Gson().toJson(map));
    }

    /**
     * 【仅文件客户端】发送可查看的文件列表
     * @param fileListData 加密的文件列表
     */
    public void sendFileList(String fileListData) {
        Map<String, Object> map = new HashMap<>();
        map.put("action", "file_list");
        map.put("data", fileListData);
        sendString(new Gson().toJson(map));
    }

    /**
     * 【仅文件客户端】发送指定位置的Packet
     * @param frame Packet详情
     * @param time Packet时间戳
     * @param position Packet位置
     */
    public void sendOrderedPacket(String frame, String time, int position) {
        // 为避免循环流量，不向使用代理的用户发送报文详情
        if (proxyUser)
            return;
        Map<String, Object> map = new HashMap<>();
        map.put("action", "ordered_packet");
        map.put("packet", frame);
        map.put("position", position);
        map.put("time", time);
        sendString(new Gson().toJson(map));
    }

    /**
     * 发送消息，所有的消息发送都必须通过这里
     * @param text 已经处理过的最终待发送消息
     */
    synchronized private void sendString(String text) {
        try {
            if (isOpen())
                session.getRemote().sendString(text);
        } catch (IOException e) {
            e.printStackTrace();
            logger.error(e.getMessage());
        }
    }

    /**
     * 转换Pcap4J的PcapNetworkInterface为自定义的网卡接口
     * @param nif PcapNetworkInterface
     * @return 自定义的网卡接口
     */
    public static Interface loadInterfaceFromNif(PcapNetworkInterface nif) {
        if (nif == null)
            return null;
        Interface inter = new Interface();
        inter.name = nif.getName();
        inter.description = nif.getDescription();
        for (PcapAddress address : nif.getAddresses())
            inter.addresses.add(address.getAddress().getHostAddress());
        return inter;
    }

    private static class Message {
        private String action, data;
        private Map<String, String> extra = new HashMap<>();
    }

    private static class Command {
        private String command;
        private Map<String, Object> extra = new HashMap<>();

        @Override
        public String toString() {
            return "{" + "command=" + command + ", extra=" + extra + '}';
        }
    }

    public static class Interface {
        private String name;
        private String description;
        private List<String> addresses = new ArrayList<>();

        public String getName() {
            return name;
        }
        public String getDescription() {
            return description;
        }
        public List<String> getAddresses() {
            return addresses;
        }
    }
}
