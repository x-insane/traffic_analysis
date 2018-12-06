package com.xinsane.traffic_analysis.data.handler;

import com.xinsane.traffic_analysis.data.CaptureInformation;
import com.xinsane.traffic_analysis.websocket.WSHandler;
import org.eclipse.jetty.websocket.api.Session;

public interface SourceHandler {
    void bindWebSocketHandler(WSHandler handler);
    CaptureInformation getInformation();
}
