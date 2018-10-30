package com.xinsane.traffic_analysis.data;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

public class FixedNumberDumper {
    private static final Logger logger = LoggerFactory.getLogger(FixedNumberDumper.class);
    private static String dumper_dir = "./dump/";
    private static int max_number = 10000;
    public static void config(String dumper_dir, int max_number) {
        FixedNumberDumper.dumper_dir = dumper_dir;
        FixedNumberDumper.max_number = max_number;
    }

    private FreshHandle callback;
    private PcapDumper dumper;
    private int number = 0;

    FixedNumberDumper(FreshHandle callback) {
        this.callback = callback;
    }

    void addPacket(Packet packet) {
        if (dumper == null || !dumper.isOpen())
            createNewFile();
        try {
            dumper.dump(packet);
            number ++;
            if (number >= max_number)
                createNewFile();
        } catch (NotOpenException e) {
            e.printStackTrace();
        }
    }

    void close() {
        if (dumper != null && dumper.isOpen())
            dumper.close();
    }

    private void createNewFile() {
        if (dumper != null && dumper.isOpen())
            dumper.close();
        dumper = null;
        PcapHandle handle = callback.getHandle();
        if (handle != null && handle.isOpen()) {
            try {
                SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
                String dumper_name = dumper_dir + callback.getDumperName() + "/";
                File file = new File(dumper_name);
                if (!file.exists())
                    if (!file.mkdirs())
                        logger.error("can not create dir: " + file.getAbsolutePath());
                dumper = handle.dumpOpen(dumper_name + df.format(new Date()) + ".pcap");
            } catch (PcapNativeException | NotOpenException e) {
                e.printStackTrace();
            }
        }
        number = 0;
    }

    interface FreshHandle {
        PcapHandle getHandle();
        String getDumperName();
    }
}
