package com.xinsane.traffic_analysis;

import com.xinsane.traffic_analysis.data.dumper.Dumper;
import com.xinsane.traffic_analysis.helper.AESCryptHelper;
import com.xinsane.traffic_analysis.helper.ArgumentsResolver;
import com.xinsane.traffic_analysis.websocket.WSHandler;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.server.handler.SecuredRedirectHandler;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class Application {
    private static final Logger logger = LoggerFactory.getLogger(Application.class);
    public static ArgumentsResolver.Result config = new ArgumentsResolver.Result();
    public static int port = 8090;
    public static String dumper_dir = "./dump/";
    public static int slice_number = 500;
    private static String keystore_path = "./certs/keystore";
    private static String keystore_password = "traffic.xinsane.com";

    public static void main(String[] args) throws Exception {
        config = ArgumentsResolver.resolve(args);
        if (config.args.size() > 0)
            port = Integer.parseInt(config.args.get(0));
        if (config.flags.containsKey("dump"))
            dumper_dir = config.flags.get("dump");
        if (config.flags.containsKey("slice"))
            slice_number = Integer.parseInt(config.flags.get("slice"));
        if (config.flags.containsKey("keystore_path"))
            keystore_path = config.flags.get("keystore_path");
        if (config.flags.containsKey("keystore_password"))
            keystore_password = config.flags.get("keystore_password");
        generateKey();
        createDumpDir();
        startWeb();
    }

    private static void generateKey() {
        String keyString = bytes2Hex(AESCryptHelper.key.getEncoded());
        logger.debug("generate a new key: " + keyString);
        // 把生成的密钥写入文件
        File file = new File("./key.txt");
        try {
            if (file.exists()) {
                if (!file.delete())
                    logger.error("can not delete old key file.");
            }
            if (file.createNewFile()) {
                file.deleteOnExit(); // 程序结束后删除
                BufferedWriter out = new BufferedWriter(new FileWriter(file));
                out.write(keyString);
                out.flush();
                out.close();
            } else
                logger.error("can not write key to the file: " + file.getAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
            logger.error("can not write key to the file: " + file.getAbsolutePath());
        }
    }

    private static String bytes2Hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for(byte b : bytes)
            builder.append(String.format("%02x", b & 0xff));
        return builder.toString();
    }

    private static void startWeb() throws Exception {
        Server server = new Server();

        // SSL Context Factory
        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setKeyStorePath(keystore_path);
        sslContextFactory.setKeyStorePassword(keystore_password);

        // HTTP Configuration
        HttpConfiguration http_config = new HttpConfiguration();
        http_config.setSecureScheme("https");
        http_config.setSecurePort(port);

        // HTTPS Configuration
        HttpConfiguration https_config = new HttpConfiguration(http_config);
        https_config.addCustomizer(new SecureRequestCustomizer());

        // HTTPS Connector
        ServerConnector httpsConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                new HttpConnectionFactory(https_config));
        httpsConnector.setPort(port);
        server.addConnector(httpsConnector);

        HandlerList handlerList = new HandlerList();

        // HTTP => HTTPS
        ContextHandler redirectHandler = new ContextHandler();
        redirectHandler.setContextPath("/");
        redirectHandler.setHandler(new SecuredRedirectHandler());
        handlerList.addHandler(redirectHandler);

        // Resource Handler
        ResourceHandler resourceHandler = new ResourceHandler();
        resourceHandler.setDirectoriesListed(true);
        String resource_path = Application.class.getResource("/static").toString();
        logger.debug("resource_path: {}", resource_path);
        resourceHandler.setResourceBase(resource_path);
        handlerList.addHandler(resourceHandler);

        // WebSocket Handler
        ContextHandler wsHandler = new ContextHandler();
        wsHandler.setContextPath("/websocket");
        wsHandler.setHandler(new WSHandler());
        handlerList.addHandler(wsHandler);

        // GZIP Support
        GzipHandler gzip = new GzipHandler();
        gzip.setHandler(handlerList);
        server.setHandler(gzip);

        // Start Server
        server.setStopAtShutdown(true);
        server.start();
    }

    private static void createDumpDir() {
        File dir = new File(Dumper.dumper_dir);
        if (!dir.exists()) {
            if (!dir.mkdirs()) {
                logger.error("无法创建dump目录！");
                System.exit(-1);
            }
        }
    }

}
