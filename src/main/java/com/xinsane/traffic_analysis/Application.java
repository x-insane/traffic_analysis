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
import java.util.HashMap;
import java.util.Map;

public class Application {
    private static final Logger logger = LoggerFactory.getLogger(Application.class);
    public static ArgumentsResolver.Result config = new ArgumentsResolver.Result();
    public static int http_port = -1;
    public static int https_port = -1;
    public static String dumper_dir = "./dump/";
    public static int slice_number = 500;
    private static String keystore_path = "./certs/keystore";
    private static String keystore_password = "";
    public static boolean no_aes = false;

    public static void main(String[] args) {
        try {
            resolveArguments(args);
            generateKey();
            createDumpDir();
            startWeb();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private static void resolveArguments(String[] args) {
        Map<String, String> validOptions = new HashMap<>();
        validOptions.put("http", "specify the http listen port.");
        validOptions.put("https", "specify the https listen port.");
        validOptions.put("dump", "specify the pcap files directory. default ./dump/");
        validOptions.put("slice", "specify how many packets per pcap file in file mode. default 500");
        validOptions.put("keystore", "specify the path of SSL keystore file. default ./certs/keystore");
        validOptions.put("keystore_pass", "specify the password of SSL keystore file.");
        Map<String, String> validFeatures = new HashMap<>();
        validFeatures.put("no_aes", "data will be transferred without encryption if --no_aes is set");
        config = ArgumentsResolver.resolve(args, validOptions, validFeatures);

        if (config.args.size() > 0) {
            ArgumentsResolver.die("Unknown arguments. You can use this program with options and features below.",
                    validOptions, validFeatures);
        }

        if (config.options.containsKey("http")) {
            http_port = Integer.parseInt(config.options.get("http"));
            logger.debug("http port will be listening on " + http_port);
        }
        if (config.options.containsKey("https")) {
            https_port = Integer.parseInt(config.options.get("https"));
            logger.debug("https port will be listening on " + https_port);
        }
        if (config.options.containsKey("dump"))
            dumper_dir = config.options.get("dump");
        if (config.options.containsKey("slice"))
            slice_number = Integer.parseInt(config.options.get("slice"));
        if (config.options.containsKey("keystore"))
            keystore_path = config.options.get("keystore");
        if (config.options.containsKey("keystore_pass"))
            keystore_password = config.options.get("keystore_pass");

        if (config.features.containsKey("no_aes")) {
            no_aes = true;
            logger.debug("AES encryption turn off. Data transfer may be at risk.");
        }

        if (http_port <= 0 && https_port <= 0) {
            ArgumentsResolver.die("You should specify either -http or -https option at least.",
                    validOptions, validFeatures);
        }
        if (http_port > 0 && no_aes) {
            logger.warn("it will be at risk to specify a http port with --no_aes set.");
        }
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

        if (http_port > 0) {
            // HTTP Connector
            ServerConnector httpConnector = new ServerConnector(server);
            httpConnector.setPort(http_port);
            server.addConnector(httpConnector);
        }

        if (https_port > 0) {
            // HTTPS Configuration
            HttpConfiguration https_config = new HttpConfiguration();
            https_config.setSecureScheme("https");
            https_config.setSecurePort(https_port);
            https_config.addCustomizer(new SecureRequestCustomizer());

            // HTTPS Connector
            ServerConnector httpsConnector = new ServerConnector(server,
                    new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                    new HttpConnectionFactory(https_config));
            httpsConnector.setPort(https_port);
            server.addConnector(httpsConnector);
        }

        HandlerList handlerList = new HandlerList();

        // Resource Handler
        ResourceHandler resourceHandler = new ResourceHandler();
        resourceHandler.setDirectoriesListed(true);
        String resource_path = Application.class.getResource("/static").toString();
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
