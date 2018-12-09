package com.xinsane.traffic_analysis.data.dumper;

import com.xinsane.traffic_analysis.Application;
import com.xinsane.traffic_analysis.data.CaptureInformation;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.UUID;

/**
 * 用于将一个大的Packet文件拆分成多个小文件
 * 每个小文件含有的Packet数量固定
 */
public class SliceDumper {
    private static final Logger logger = LoggerFactory.getLogger(SliceDumper.class);

    private PcapDumper dumper;
    private int packetNumber = 0;
    private int fileNumber = 0;
    private PcapHandle handle;
    private String tmpDir;
    private CaptureInformation information = new CaptureInformation();
    private SliceFileCompleteCallback callback = null;
    private Thread thread = null;

    /**
     * 通过文件创建
     * @param filename 文件名
     * @param filter 过滤器
     */
    public SliceDumper(String filename, String filter, SliceFileCompleteCallback callback) {
        this.callback = callback;
        thread = new Thread(() -> {
            try {
                createTmpDir();
                handle = Pcaps.openOffline(Application.dumper_dir + filename);
                if (filter != null)
                    handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
                handle.loop(-1, this::handlePacket);
            } catch (PcapNativeException | NotOpenException | InterruptedException e) {
                e.printStackTrace();
            } finally {
                closeCurrentFile();
                if (handle != null)
                    handle.close();
                handle = null;
            }
            if (this.callback != null)
                this.callback.onComplete();
            thread = null;
        });
        thread.start();
    }

//    /**
//     * 通过正在捕获的接口创建
//     * @param handle 捕获接口的PcapHandle
//     */
//    public SliceDumper(PcapHandle handle) {
//        this.handle = handle;
//        createTmpDir();
//    }

    private void handlePacket(Packet packet) {
        if (fileNumber == 0 && packetNumber == 0)
            information.setStartTime(handle.getTimestamp().getTime());
        information.setEndTime(handle.getTimestamp().getTime());
        information.count(packet);
        if (dumper == null || !dumper.isOpen())
            createNewFile();
        try {
            dumper.dump(packet);
            packetNumber++;
            if (packetNumber >= Application.slice_number)
                createNewFile();
        } catch (NotOpenException e) {
            e.printStackTrace();
        }
    }

    private void createTmpDir() {
        tmpDir = Application.dumper_dir + UUID() + "/"; // 临时文件夹
        File file = new File(tmpDir);
        if (!file.exists())
            if (!file.mkdirs())
                logger.error("can not create dir: " + file.getAbsolutePath());
    }

    private void createNewFile() {
        closeCurrentFile();
        fileNumber ++;
        if (handle != null && handle.isOpen()) {
            try {
                String filename = tmpDir + String.format("%08d", fileNumber) + ".pcap"; // 临时文件名
                dumper = handle.dumpOpen(filename);
            } catch (PcapNativeException | NotOpenException e) {
                logger.error(e.getMessage());
            }
        }
        packetNumber = 0;
    }

    public String getTmpFilename(int fileIndex) {
        return tmpDir + String.format("%08d", fileIndex) + ".pcap";
    }

    public CaptureInformation getInformation() {
        return information;
    }

    private void closeCurrentFile() {
        if (dumper != null && dumper.isOpen()) {
            try {
                dumper.flush();
            } catch (PcapNativeException | NotOpenException e) {
                logger.error("error in flush a slice dump file: " + e.getMessage());
            }
            dumper.close();
        }
        dumper = null;
    }

    public void clearTmpFiles() {
        if (thread != null)
            thread.interrupt();
        new Thread(() -> {
            try {
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            for (int i = 1; i <= fileNumber; ++i) {
                String filename = getTmpFilename(i);
                File file = new File(filename);
                if (file.exists()) {
                    if (!file.delete())
                        logger.error("can not delete temporary file: " + file.getName());
                }
            }
            File file = new File(tmpDir);
            if (!file.delete())
                logger.error("can not delete temporary directory: " + file.getName());
            else
                logger.debug("delete temporary directory: " + file.getName());
        }).start();
    }

    private String UUID() {
        return UUID.randomUUID().toString();
    }

    public interface SliceFileCompleteCallback {
        void onComplete();
    }
}
