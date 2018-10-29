package com.xinsane.traffic_analysis.data;

import com.google.gson.Gson;
import com.xinsane.traffic_analysis.websocket.WSHandler;
import org.eclipse.jetty.websocket.api.RemoteEndpoint;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class CaptureThread extends Thread {

    private PcapNetworkInterface nif;
    private PcapHandle handle;

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
            handle.loop(-1, (PacketListener) packet -> {
                // 控制台输出
//                System.out.println(handle.getTimestamp());
//                System.out.println(packet);

                // WebSocket
                if (WSHandler.session != null && WSHandler.session.isOpen()) {
                    RemoteEndpoint remote = WSHandler.session.getRemote();
                    Map<String, Object> map = new HashMap<>();
                    map.put("packet", packet);
                    map.put("time", handle.getTimestamp());
                    try {
                        remote.sendString(new Gson().toJson(map));
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                // 文件

            });
        } catch (InterruptedException | NotOpenException | PcapNativeException e) {
            e.printStackTrace();
        }
    }

    public void startCapture() {
        start();
    }

    public void stopCapture() {
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }
    }

}
