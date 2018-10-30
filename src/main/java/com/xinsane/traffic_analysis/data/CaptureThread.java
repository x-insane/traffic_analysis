package com.xinsane.traffic_analysis.data;

import com.google.gson.Gson;
import com.xinsane.traffic_analysis.data.exception.PacketOfSelfException;
import com.xinsane.traffic_analysis.data.exception.UnknownPacketException;
import com.xinsane.traffic_analysis.data.packet.SFrame;
import com.xinsane.traffic_analysis.websocket.WSHandler;
import org.eclipse.jetty.websocket.api.RemoteEndpoint;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CaptureThread extends Thread implements FixedNumberDumper.FreshHandle {
    private static final Logger logger = LoggerFactory.getLogger(CaptureThread.class);

    private static List<InetAddress> addresses;
    public static List<InetAddress> getAddresses() {
        return addresses;
    }

    private PcapNetworkInterface nif;
    private PcapHandle handle;
    private String captureName;
    private FixedNumberDumper dumper = new FixedNumberDumper(this);

    public boolean selectNetworkInterfaceByCmd() {
        // 选取网卡
        try {
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public void run() {
        if (nif == null)
            return;

        int snapLen = 65536;
        PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
        int timeout = 10;

        try {
            handle = nif.openLive(snapLen, mode, timeout);
            addresses = nif.getAddresses().stream()
                    .map(PcapAddress::getAddress)
                    .collect(Collectors.toList());
            handle.loop(-1, (PacketListener) packet -> {
                // 控制台输出
                // System.out.println(handle.getTimestamp());
                // System.out.println(packet);

                SFrame frame = null;
                try {
                    frame = new SFrame();
                    frame.load(packet);
                } catch (UnknownPacketException e) {
                    logger.debug("capture an unknown packet.");
                    logger.debug(new Gson().toJson(packet));
                } catch (PacketOfSelfException e) {
                    return;
                }

                // WebSocket
                if (frame != null && WSHandler.session != null && WSHandler.session.isOpen()) {
                    RemoteEndpoint remote = WSHandler.session.getRemote();
                    Map<String, Object> map = new HashMap<>();
                    map.put("packet", frame);
                    map.put("time", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS")
                            .format(handle.getTimestamp().getTime()));
                    try {
                        remote.sendString(new Gson().toJson(map));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                // 文件
                dumper.addPacket(packet);
            });
        } catch (InterruptedException | NotOpenException | PcapNativeException e) {
            e.printStackTrace();
        }
    }

    @Override
    public PcapHandle getHandle() {
        if (handle != null && handle.isOpen())
            return handle;
        return null;
    }

    @Override
    public String getDumperName() {
        return captureName;
    }

    public void startCapture(String captureName) {
        this.captureName = captureName;
        start();
    }

    public void stopCapture() {
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
                dumper.close();
                addresses = null;
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }
    }

}
