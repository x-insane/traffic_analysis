package com.xinsane.traffic_analysis;

import com.xinsane.traffic_analysis.data.CaptureThread;
import com.xinsane.traffic_analysis.web.ShutDownServlet;
import com.xinsane.traffic_analysis.websocket.WSHandler;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Application {
    private static final Logger logger = LoggerFactory.getLogger(Application.class);

    private static CaptureThread capture = new CaptureThread();

    public static void main(String[] args) throws Exception {
        int port = 8090;
        if (args.length > 0)
            port = Integer.parseInt(args[0]);
        startWeb(port);
        startCapture();
    }

    private static void startCapture() {
        if (!capture.selectNetworkInterfaceByCmd())
            logger.error("select network interface by command line fail.");
        capture.startCapture();
    }

    private static void startWeb(int port) throws Exception {
        Server server = new Server(port);

        ServletContextHandler handler = new ServletContextHandler(ServletContextHandler.SESSIONS);
        handler.setContextPath("/");
        handler.addServlet(new ServletHolder(new ShutDownServlet()), "/shutdown");

        ResourceHandler resource_handler = new ResourceHandler();
        resource_handler.setDirectoriesListed(true);
        String resource_path = Application.class.getResource("/static").toString();
        logger.debug("resource_path: {}", resource_path);
        resource_handler.setResourceBase(resource_path);

        ContextHandler ws_handler = new ContextHandler();
        ws_handler.setContextPath("/websocket");
        ws_handler.setHandler(new WSHandler());

        HandlerList handlers = new HandlerList();
        handlers.setHandlers(new Handler[] { ws_handler, resource_handler, handler });
        server.setHandler(handlers);

        server.start();
    }

}
