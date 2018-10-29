package com.xinsane.traffic_analysis.websocket;

import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.*;
import org.eclipse.jetty.websocket.server.WebSocketHandler;
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory;

@WebSocket
public class WSHandler extends WebSocketHandler {

    public static Session session;

    @OnWebSocketClose
    public void onClose(int statusCode, String reason) {
    }

    @OnWebSocketError
    public void onError(Throwable t) {
    }

    @OnWebSocketConnect
    public void onConnect(Session session) {
        WSHandler.session = session;
    }

    @OnWebSocketMessage
    public void onMessage(String message) {
    }

    @Override
    public void configure(WebSocketServletFactory factory) {
        factory.register(WSHandler.class);
    }
}
