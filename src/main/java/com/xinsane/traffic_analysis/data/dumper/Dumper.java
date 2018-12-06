package com.xinsane.traffic_analysis.data.dumper;

import com.xinsane.traffic_analysis.Application;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;

public interface Dumper {
    String dumper_dir = Application.dumper_dir;
    int slice_number = Application.slice_number;

    void addPacket(Packet packet);
    void close();
    default void clearTmpFiles() {}

    interface HandlerInformation {
        PcapHandle getHandle();
        String getDumperName();
    }
}
