package com.xinsane.traffic_analysis.data.handler;

import com.google.gson.Gson;
import com.xinsane.traffic_analysis.Application;
import com.xinsane.traffic_analysis.data.CaptureInformation;
import com.xinsane.traffic_analysis.data.dumper.SliceDumper;
import com.xinsane.traffic_analysis.data.exception.UnknownPacketException;
import com.xinsane.traffic_analysis.data.packet.SFrame;
import com.xinsane.traffic_analysis.helper.AESCryptHelper;
import com.xinsane.traffic_analysis.websocket.WSHandler;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

public class PacketFileHandler implements SourceHandler {
    private static final Logger logger = LoggerFactory.getLogger(PacketFileHandler.class);

    private WSHandler websocket;
    private SliceDumper sliceDumper;

    @Override
    public void bindWebSocketHandler(WSHandler handler) {
        websocket = handler;
    }

    @Override
    public CaptureInformation getInformation() {
        return sliceDumper == null ? null : sliceDumper.getInformation();
    }

    public void listFiles() {
        File dir = new File(Application.dumper_dir);
        List<FileInfo> files = new ArrayList<>();
        File[] all = dir.listFiles();
        if (all != null) {
            // 按修改时间从新到旧排序
            Arrays.sort(all, (f1, f2) -> {
                long diff = f1.lastModified() - f2.lastModified();
                if (diff == 0)
                    return 0;
                else if (diff > 0)
                    return -1;
                else
                    return 1;
            });
            for (File file : all) {
                // 忽略正在捕获的文件
                if (file.getName().equals(CaptureHandler.getInstance().getDumperName()))
                    continue;
                if (file.isFile() && file.getName().toLowerCase().endsWith(".pcap")) {
                    FileInfo info = new FileInfo();
                    info.name = file.getName();
                    info.size = file.length();
                    files.add(info);
                }
            }
        }
        websocket.sendFileList(AESCryptHelper.encrypt(new Gson().toJson(files)));
    }

    public void deleteFiles(List files) {
        for (Object item : files) {
            if (item instanceof String) {
                String filename = item.toString();
                File file = new File(Application.dumper_dir + filename);
                if (filename.toLowerCase().endsWith(".pcap") && file.exists() && file.isFile()) {
                    if (file.delete())
                        logger.debug("delete file " + file.getAbsolutePath());
                    else
                        logger.error("can not delete file " + file.getAbsolutePath());
                }
            }
        }
        listFiles();
    }

    public void bindFile(String filename, String filter) {
        unbindFile();
        AtomicBoolean complete = new AtomicBoolean(false);
        this.sliceDumper = new SliceDumper(filename, filter, () -> {
            complete.set(true);
            websocket.sendStatistics();
        });
        new Thread(() -> {
            boolean send = false;
            while (!complete.get()) {
                try {
                    Thread.sleep(1000); // 每秒更新状态
                    websocket.sendStatistics();
                    if (!send) {
                        requestPackets(0, 100);
                        send = true;
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public void unbindFile() {
        if (sliceDumper != null) {
            sliceDumper.clearTmpFiles();
            sliceDumper = null;
        }
    }

    public void requestPackets(final int start, int number) {
        int total = sliceDumper.getInformation().getTotalCount();
        if (start + number > total) {
            logger.error("request packets out of bound. total="
                    + total + ". request start=" + start + ", number=" + number + ".");
            if (start >= total)
                return;
            number = total - start;
        }
        final int last = start + number;
        Thread thread = new Thread(() -> {
            // 待访问第一个文件的位置的偏移量
            int fileIndex = start / Application.slice_number;
            // 忽略第一个文件的多少个包
            int packetOffset = start % Application.slice_number;
            // 已经处理的有效包
            int index = 0;
            PcapHandle handle = null;
            try {
                while (index + start < last) {
                    if (sliceDumper == null)
                        break;
                    handle = Pcaps.openOffline(sliceDumper.getTmpFilename(++fileIndex));
                    while (packetOffset > 0) {
                        if (handle.getNextPacket() == null)
                            break;
                        packetOffset --;
                    }
                    if (packetOffset == 0) {
                        Packet packet = handle.getNextPacket();
                        while (packet != null && ++index + start <= last) {
                            try {
                                SFrame frame = new SFrame();
                                frame.load(packet);
                                websocket.sendOrderedPacket(AESCryptHelper.encrypt(new Gson().toJson(frame)),
                                        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS")
                                                .format(handle.getTimestamp().getTime()),
                                        index + start - 1);
                            } catch (UnknownPacketException e) {
                                logger.error(e.getMessage());
                            }
                            packet = handle.getNextPacket();
                        }
                    }
                    handle.close();
                    handle = null;
                }
            } catch (PcapNativeException | NotOpenException e) {
                e.printStackTrace();
            } finally {
                if (handle != null)
                    handle.close();
            }
        });
        thread.setDaemon(true);
        thread.start();
    }

    private static class FileInfo {
        private String name;
        private long size;
    }
}
