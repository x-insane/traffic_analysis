import {notification} from "antd";
import {decrypt, encrypt, md5} from "../../common/Crypto";

let ws_url = null;

if (process.env.NODE_ENV === "development") {
    ws_url = (window.location.protocol.indexOf("s") > -1 ? "wss://" : "ws://")
        + window.location.hostname + ":12611/websocket/";
    // ws_url = "wss://localhost:8002/websocket/";
}
else {
    ws_url = (window.location.protocol.indexOf("s") > -1 ? "wss://" : "ws://")
        + window.location.host + "/websocket/";
}

const getSrcIP = packet => {
    if (packet.ethernet) {
        if (packet.ethernet.ipv4)
            return packet.ethernet.ipv4.header.src;
        if (packet.ethernet.ipv6)
            return packet.ethernet.ipv6.header.src;
    }
    if (packet.ethernet.arp)
        return packet.ethernet.arp.header.srcProtocol;
    return ""
};

const getDstIP = packet => {
    if (packet.ethernet) {
        if (packet.ethernet.ipv4)
            return packet.ethernet.ipv4.header.dst;
        if (packet.ethernet.ipv6)
            return packet.ethernet.ipv6.header.dst;
    }
    if (packet.ethernet.arp)
        return packet.ethernet.arp.header.dstProtocol;
    return ""
};

const getPacketType = packet => {
    if (packet.ethernet) {
        if (packet.ethernet.arp) {
            if (packet.ethernet.arp.header.operation === 1)
                return "ARP REQUEST";
            else if (packet.ethernet.arp.header.operation === 2)
                return "ARP REPLY";
            return "ARP";
        }
        if (packet.ethernet.ipv4 || packet.ethernet.ipv6)
            return packet.ethernet[packet.ethernet.type].type.toUpperCase();
    }
    return ""
};

class Socket {

    timer = null;

    constructor(props) {
        this.props = props;
        this.initWebSocket(false);
    }

    initWebSocket = (reconnect) => {
        this.ws = new WebSocket(ws_url);
        this.ws.onerror = () => {
            if (!reconnect && this.ws.readyState !== 1)
                this.onSocketError("无法连接到服务器")
        };
        this.ws.onopen = () => {
            this.ws_notification = true;
            if (reconnect) {
                notification.success({
                    message: "已重新连接",
                    description: "已成功重新连接到服务器",
                    duration: null,
                });
                this.ws_notification = true
            }
            if (this.props.onReconnected)
                this.props.onReconnected()
        };
        this.ws.onclose = this.onClose;
        this.ws.onmessage = this.onMessage;
    };

    close = () => {
        this.ws.onclose = null;
        this.ws.close();
        this.ws = null
    };

    sendCommand = (command, extra) => {
        if (!this.ws)
            return console.log("socket closed. can not send commend " + command);
        this.ws.send(JSON.stringify({
            action: "command",
            data: encrypt(JSON.stringify({
                command, extra
            }))
        }))
    };

    startCapture = (index, filter) => {
        this.sendCommand("start_capture", {
            index,
            filter
        })
    };

    stopCapture = () => {
        this.sendCommand("stop_capture")
    };

    requestCaptureStatus = () => {
        this.sendCommand("capture_status")
    };

    listInterfaces = () => {
        this.sendCommand("list_interfaces")
    };

    requestStatistics = () => {
        if (this.ws)
            this.sendCommand("statistics")
    };

    requestFileList = () => {
        this.sendCommand("list_files")
    };

    deleteFiles = files => {
        this.sendCommand("delete_files", {
            files
        })
    };

    bindFile = (filename, filter) => {
        this.sendCommand("bind_file", {
            filename, filter
        })
    };

    unbindFile = () => {
        this.sendCommand("unbind_file")
    };

    requestOrderedPackets = (start, number) => {
        this.sendCommand("request_packets", {
            start, number
        })
    };

    onClose = () => {
        if (this.ws_notification) {
            notification.error({
                message: "连接已断开",
                description: "与服务器的连接中断，无法获取新数据",
                duration: null
            });
        }
        this.ws_notification = false;
        this.ws = null;
        setTimeout(() => {
            this.initWebSocket(true)
        }, 1000)
    };

    onSocketError = error => {
        if (this.props.onSocketError)
            this.props.onSocketError(error)
    };

    onMessage = event => {
        let message = JSON.parse(event.data);
        switch (message.action) {
            case "pong":
                if (this.timer) {
                    clearTimeout(this.timer);
                    this.timer = null
                }
                setTimeout(() => {
                    this.ws.send(JSON.stringify({
                        action: "ping"
                    }))
                }, 1000);
                // 30秒未有回报，判定离线
                this.timer = setTimeout(() => {
                    this.ws.close()
                }, 30000);
                break;
            case "hello":
                if (encrypt(message.seed) === message.cipher) {
                    this.ws.send(JSON.stringify({
                        action: "hello",
                        data: encrypt(md5(message.seed)),
                        extra: {
                            type: this.props.type
                        }
                    }))
                } else {
                    this.onSocketError("密钥错误")
                }
                break;
            case "verify":
                if (message.result === true) {
                    if (this.props.onConnected)
                        this.props.onConnected()
                } else {
                    this.onSocketError("密钥错误")
                }
                break;
            case "status":
                const status = JSON.parse(decrypt(message.data));
                if (this.props.onCaptureStatus) {
                    this.props.onCaptureStatus(status, () => {
                        this.sendCommand(status.running ? "statistics" : "list_interfaces")
                    })
                }
                break;
            case "interfaces":
                if (this.props.onInterfaces) {
                    const interfaces = JSON.parse(decrypt(message.interfaces));
                    this.props.onInterfaces(interfaces)
                }
                break;
            case "packet":
                if (this.props.onPacket) {
                    let item = {};
                    item.packet = JSON.parse(decrypt(message.packet));
                    item.time = message.time;
                    item.src = getSrcIP(item.packet);
                    item.dst = getDstIP(item.packet);
                    item.type = getPacketType(item.packet);
                    this.props.onPacket(item)
                }
                break;
            case "ordered_packet": {
                if (this.props.onOrderedPacket) {
                    let item = {};
                    item.packet = JSON.parse(decrypt(message.packet));
                    item.time = message.time;
                    item.time = "# " + (message.position + 1);
                    item.src = getSrcIP(item.packet);
                    item.dst = getDstIP(item.packet);
                    item.type = getPacketType(item.packet);
                    this.props.onOrderedPacket(item, message.position);
                }
                break;
            }
            case "statistics":
                if (this.props.onStatistics) {
                    message.statistics = JSON.parse(decrypt(message.statistics));
                    const typeStatistics = [
                        {
                            x: "ARP",
                            y: message.statistics.statistics.arp || 0
                        },
                        {
                            x: "TCP",
                            y: message.statistics.statistics.tcp || 0
                        },
                        {
                            x: "UDP",
                            y: message.statistics.statistics.udp || 0
                        },
                        {
                            x: "ICMP",
                            y: message.statistics.statistics.icmp || 0
                        }
                    ];
                    const ipStatistics = [
                        {
                            x: "IPv4/" + (message.statistics.statistics.ipv4 || 0),
                            y: message.statistics.statistics.ipv4 || 0
                        },
                        {
                            x: "IPv6/" + (message.statistics.statistics.ipv6 || 0),
                            y: message.statistics.statistics.ipv6 || 0
                        }
                    ];
                    this.props.onStatistics(message.statistics, message.time, typeStatistics, ipStatistics)
                }
                break;
            case "file_list":
                if (this.props.onFileList)
                    this.props.onFileList(JSON.parse(decrypt(message.data)));
                break;
            case "info":
                notification.info({
                    message: "来自服务器的提示",
                    description: decrypt(message.info),
                    duration: null
                });
                break;
            case "error":
                notification.error({
                    message: "来自服务器的错误",
                    description: decrypt(message.error) || "Unknown Error",
                    duration: null
                });
                break;
            default:
                console.log(message);
                break;
        }
    };
}

export default Socket;