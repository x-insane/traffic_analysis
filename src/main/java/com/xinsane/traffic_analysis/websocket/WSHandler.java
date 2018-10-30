package com.xinsane.traffic_analysis.websocket;

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
    }

    @Override
    public void configure(WebSocketServletFactory factory) {
        factory.register(WSHandler.class);
    }
}
