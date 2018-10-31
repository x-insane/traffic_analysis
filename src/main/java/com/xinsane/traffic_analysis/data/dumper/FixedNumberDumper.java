package com.xinsane.traffic_analysis.data.dumper;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class FixedNumberDumper {
    private static final Logger logger = LoggerFactory.getLogger(FixedNumberDumper.class);

    private static String dumper_dir = "./dump/";
    private static int slice_number = 500;
    public static void config(String dumper_dir, int slice_number) {
        FixedNumberDumper.dumper_dir = dumper_dir;
        FixedNumberDumper.slice_number = slice_number;
    }

    private FreshHandle callback;
    private PcapDumper mainDumper;
    private PcapDumper dumper;
    private int number = 0;
    private String tmpDir;
    private List<String> filenames = new ArrayList<>();

    public FixedNumberDumper(FreshHandle callback) {
        this.callback = callback;
        tmpDir = dumper_dir + UUID() + "/"; // 临时文件夹
        File file = new File(tmpDir);
        if (!file.exists())
            if (!file.mkdirs())
                logger.error("can not create dir: " + file.getAbsolutePath());
    }

    public void addPacket(Packet packet) {
        try {
            if (mainDumper == null) {
                String filename = dumper_dir + callback.getDumperName() + ".pcap";
                mainDumper = callback.getHandle().dumpOpen(filename);
            }
            mainDumper.dump(packet);
        } catch (NotOpenException | PcapNativeException e) {
            e.printStackTrace();
        }

        if (dumper == null || !dumper.isOpen())
            createNewFile();
        try {
            dumper.dump(packet);
            number ++;
            if (number >= slice_number) {
                createNewFile();
                mainDumper.flush();
            }
        } catch (NotOpenException | PcapNativeException e) {
            e.printStackTrace();
        }
    }

    public void close() {
        if (dumper != null && dumper.isOpen())
            dumper.close();
    }

    public void deleteTmpFiles() {
        for (String filename : filenames) {
            File file = new File(filename);
            if (file.exists()) {
                if (!file.delete())
                    logger.error("can not delete temporary file: " + file.getName());
                else
                    logger.debug("delete temporary file: " + file.getName());
            }
        }
        File file = new File(tmpDir);
        if (!file.delete())
            logger.error("can not delete temporary directory: " + file.getName());
        else
            logger.debug("delete temporary directory: " + file.getName());
    }

    private void createNewFile() {
        if (dumper != null && dumper.isOpen())
            dumper.close();
        dumper = null;
        PcapHandle handle = callback.getHandle();
        if (handle != null && handle.isOpen()) {
            try {
                SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
                String filename = tmpDir + df.format(new Date()) + ".pcap"; // 临时文件名
                dumper = handle.dumpOpen(filename);
                filenames.add(filename);
            } catch (PcapNativeException | NotOpenException e) {
                e.printStackTrace();
            }
        }
        number = 0;
    }

    private String UUID() {
        return UUID.randomUUID().toString();
    }

    public interface FreshHandle {
        PcapHandle getHandle();
        String getDumperName();
    }
}
