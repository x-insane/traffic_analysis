package com.xinsane.traffic_analysis.websocket;

import com.google.gson.Gson;
import com.xinsane.traffic_analysis.data.capture.CaptureThread;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.*;
import org.eclipse.jetty.websocket.server.WebSocketHandler;
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@WebSocket
public class WSHandler extends WebSocketHandler {
    private static final Logger logger = LoggerFactory.getLogger(WSHandler.class);
    public static Session session;

    private Session _session;

    @OnWebSocketClose
    public void onClose(int statusCode, String reason) {
    }

    @OnWebSocketError
    public void onError(Throwable t) {
    }

    @OnWebSocketConnect
    public void onConnect(Session session) {
        WSHandler.session = session;
        _session = session;
    }

    @OnWebSocketMessage
    public void onMessage(String message) {
        logger.debug("from socket: " + message);
        Message msg = new Gson().fromJson(message, Message.class);
        if (msg == null)
            return;
        switch (msg.cmd) {
            case "login":
                break;
            case "command":
                switch (msg.data) {
                    case "stop_capture":
                        CaptureThread.getInstance().stopCapture();
                        break;
                }
                break;
        }
    }

    @Override
    public void configure(WebSocketServletFactory factory) {
        factory.register(WSHandler.class);
    }

    public static class Message {
        private String cmd, data;

        public String getCmd() {
            return cmd;
        }

        public void setCmd(String cmd) {
            this.cmd = cmd;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }
    }
}
