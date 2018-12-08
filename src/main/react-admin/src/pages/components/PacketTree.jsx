import React from "react";
import { Tree } from 'antd';
const TreeNode = Tree.TreeNode;

const PacketTree = {
    raw: (packet, parent) => {},

    tcp: (packet, parent) => {
        let key = parent + "-tcp";
        let node = null;
        if (packet.type)
            node = PacketTree[packet.type](packet[packet.type], key);
        let flag = "flag: ";
        flag += packet.header.flag.urg ? "U " : ". ";
        flag += packet.header.flag.ack ? "A " : ". ";
        flag += packet.header.flag.psh ? "P " : ". ";
        flag += packet.header.flag.rst ? "R " : ". ";
        flag += packet.header.flag.syn ? "S " : ". ";
        flag += packet.header.flag.fin ? "F " : ". ";
        return <TreeNode title="TCP" key={key}>
            <TreeNode title={"src: " + packet.header.srcPort + " (" + packet.header.srcPortName + ")"}/>
            <TreeNode title={"dst: " + packet.header.dstPort + " (" + packet.header.dstPortName + ")"}/>
            <TreeNode title={flag}>
                {
                    Object.keys(packet.header.flag).map(k =>
                        <TreeNode key={k} title={k + ": " + packet.header.flag[k]}/>
                    )
                }
            </TreeNode>
            {
                Object.keys(packet.header).map(k => {
                    if (k === "srcPort" || k === "dstPort" || k === "srcPortName" || k === "dstPortName" || k === "flag")
                        return null;
                    return <TreeNode key={k}
                                     title={k + ": " + packet.header[k]}/>
                })
            }
            { node }
        </TreeNode>
    },

    udp: (packet, parent) => {
        let key = parent + "-udp";
        let node = null;
        if (packet.type)
            node = PacketTree[packet.type](packet[packet.type], key);
        return <TreeNode title="UDP" key={key}>
            <TreeNode title={"src: " + packet.header.srcPort + " (" + packet.header.srcPortName + ")"}/>
            <TreeNode title={"dst: " + packet.header.dstPort + " (" + packet.header.dstPortName + ")"}/>
            { node }
        </TreeNode>
    },

    icmp: (packet, parent, title) => {
        let key = parent;
        let node = null;
        if (packet.type)
            node = PacketTree[packet.type](packet[packet.type], key);
        return <TreeNode title={title} key={key}>
            <TreeNode title={"type: " + packet.header.type + " (" + packet.header.typeName + ")"}/>
            <TreeNode title={"code: " + packet.header.code + " (" + packet.header.codeName + ")"}/>
            <TreeNode title={"checksum: " + packet.header.checksum}/>
            { node }
        </TreeNode>
    },

    icmpv4: (packet, parent) => PacketTree.icmp(packet, parent + "icmpv4", "ICMPv4"),

    icmpv6: (packet, parent) => PacketTree.icmp(packet, parent + "icmpv6", "ICMPv6"),

    ipv4: (packet, parent) => {
        let key = parent + "-ipv4";
        let node = null;
        if (packet.type)
            node = PacketTree[packet.type](packet[packet.type], key);
        let flag = "flag: ";
        flag += packet.header.flag.reservedFlag ? "R " : ". ";
        flag += packet.header.flag.dontFragmentFlag ? "D " : ". ";
        flag += packet.header.flag.moreFragmentFlag ? "M " : ". ";
        return <TreeNode title="IPv4" key={key}>
            <TreeNode title={"src: " + packet.header.src}/>
            <TreeNode title={"dst: " + packet.header.dst}/>
            <TreeNode title={flag}>
                <TreeNode title={"reserved: " + packet.header.flag.reservedFlag}/>
                <TreeNode title={"dontFragment: " + packet.header.flag.dontFragmentFlag}/>
                <TreeNode title={"moreFragment: " + packet.header.flag.moreFragmentFlag}/>
                <TreeNode title={"fragmentOffset: " + packet.header.flag.fragmentOffset}/>
            </TreeNode>
            {
                Object.keys(packet.header).map(k => {
                    if (k === "flag" || k === "src" || k === "dst")
                        return null;
                    if (k.endsWith("Name"))
                        return null;
                    if (packet.header[k + "Name"]) {
                        return <TreeNode key={k} title={
                            k + ": " + packet.header[k] + " (" + packet.header[k + "Name"] + ")"
                        }/>
                    }
                    return <TreeNode key={k} title={k + ": " + packet.header[k] }/>
                })
            }
            { node }
        </TreeNode>
    },

    ipv6: (packet, parent) => {
        let key = parent + "-ipv6";
        let node = null;
        if (packet.type)
            node = PacketTree[packet.type](packet[packet.type], key);
        return <TreeNode title="IPv6" key={key}>
            {
                Object.keys(packet.header).map(k => <TreeNode key={k} title={
                    k + ": " + packet.header[k]
                }/>)
            }
            { node }
        </TreeNode>
    },

    arp: (packet, parent) => {
        let key = parent + "-arp";
        let node = null;
        if (packet.type)
            node = PacketTree[packet.type](packet[packet.type], key);
        return <TreeNode title="ARP" key={key}>
            {
                ["hardwareType", "protocolType", "operation"].map(name => <TreeNode key={name} title={
                    name + ": " + packet.header[name] + " (" + packet.header[name + "Name"] + ")"
                }/>)
            }
            <TreeNode title={"hardwareLength: " + packet.header.hardwareAddressLength}/>
            <TreeNode title={"protocolLength: " + packet.header.protocolAddressLength}/>
            <TreeNode title={"src MAC: " + packet.header.srcHardware}/>
            <TreeNode title={"dst MAC: " + packet.header.dstHardware}/>
            <TreeNode title={"src IP: " + packet.header.srcProtocol}/>
            <TreeNode title={"dst IP: " + packet.header.dstProtocol}/>
            { node }
        </TreeNode>
    },

    ethernet: (packet, parent) => {
        let key = (parent || "") + "-ethernet";
        let node = null;
        if (packet.type)
            node = PacketTree[packet.type](packet[packet.type], key);
        return <TreeNode title="Ethernet" key={key}>
            <TreeNode title={"src: " + packet.header.src}/>
            <TreeNode title={"dst: " + packet.header.dst}/>
            {node}
        </TreeNode>
    }
};

export default packet => {
    if (packet && packet.ethernet)
        return PacketTree.ethernet(packet.ethernet);
    return null
}