package com.xinsane.traffic_analysis.data.dumper;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultDumper implements Dumper {
    private static final Logger logger = LoggerFactory.getLogger(DefaultDumper.class);

    HandlerInformation handler;
    PcapDumper mainDumper;

    public DefaultDumper(HandlerInformation handler) {
        this.handler = handler;
    }

    @Override
    public void addPacket(Packet packet) {
        try {
            if (mainDumper == null) {
                String filename = dumper_dir + handler.getDumperName() + ".pcap";
                mainDumper = handler.getHandle().dumpOpen(filename);
            }
            mainDumper.dump(packet);
        } catch (NotOpenException | PcapNativeException e) {
            e.printStackTrace();
            logger.error(e.getMessage());
        }
    }

    @Override
    public void close() {
        if (mainDumper != null && mainDumper.isOpen())
            mainDumper.close();
    }
}
