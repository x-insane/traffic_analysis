import React from "react";
import {
    Collapse,
    Drawer,
    Icon,
    Layout,
    notification,
    Spin,
    Table,
    Tree,
    Row,
    Col,
    Radio,
    Button,
    Input
} from "antd";
import HeaderLayout from "../layout/HeaderLayout";
import FooterLayout from "../layout/FooterLayout";
import PacketTree from "../common/PacketTree";
import { Charts } from "ant-design-pro";

import { encrypt, decrypt, md5 } from '../common/Crypto.js';

import formatDate from '../common/FormatDate.js';

const { Column } = Table;
const { ChartCard, Bar, Pie } = Charts;

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

class CapturePage extends React.Component {

    state = {
        waiting: true,
        error: null,
        running: null,
        data: [],
        detail: null,
        statistics: null,
        statisticsUpdateTime: null,
        _type: [],
        // _typeKey: Math.random().toString(),
        _ip: [],
        interfaces: null,
        interface: null,
        filter: null,
        start_time: null
    };

    count = 0;
    timer = null;
    capture_index = 0;

    onMessage = event => {
        let message = JSON.parse(event.data);
        if (message.action === "hello") {
            if (encrypt(message.seed) === message.cipher) {
                this.ws.send(JSON.stringify({
                    action: "hello",
                    data: encrypt(md5(message.seed))
                }))
            } else {
                this.setState({
                    waiting: false,
                    error: "密钥错误"
                })
            }
        } else if (message.action === "verify") {
            if (message.result === true) {
                this.setState({
                    waiting: false
                });
                this.sendCommand("capture_status")
            } else {
                this.setState({
                    waiting: false,
                    error: "密钥错误"
                })
            }
        } else if (message.action === "status") {
            const status = JSON.parse(decrypt(message.data));
            if (status.running) {
                this.setState({
                    running: status.running,
                    interface: status.interface,
                    filter: status.filter
                }, () => { this.sendCommand("statistics") })
            }
            else {
                this.setState({
                    running: status.running,
                    filter: null,
                    statistics: null,
                    statisticsUpdateTime: null
                }, () => { this.sendCommand("list_interfaces") })
            }
        } else if (message.action === "interfaces") {
            const interfaces = JSON.parse(decrypt(message.interfaces));
            this.setState({
                interfaces: interfaces,
                running: false
            })
        } else if (message.action === "packet") {
            let item = {};
            item.packet = JSON.parse(decrypt(message.packet));
            item.time = message.time;
            item.key = this.count ++;
            item.src = getSrcIP(item.packet);
            item.dst = getDstIP(item.packet);
            item.type = getPacketType(item.packet);
            this.state.data.push(item);
            if (this.count >= 10000)
                delete this.state.data[this.count-10000];
            if (!this.timer) {
                this.timer = setTimeout(() => {
                    this.forceUpdate();
                    this.timer = null
                }, 1000)
            }
        } else if (message.action === "statistics") {
            if (this.state.running === true)
                setTimeout(() => this.sendCommand("statistics"), 5000);
            message.statistics = JSON.parse(decrypt(message.statistics));
            this.setState({
                statistics: message.statistics,
                statisticsUpdateTime: message.time,
                _type: [
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
                ],
                // _typeKey: Math.random().toString(),
                _ip: [
                    {
                        x: "IPv4/" + (message.statistics.statistics.ipv4 || 0),
                        y: message.statistics.statistics.ipv4 || 0
                    },
                    {
                        x: "IPv6/" + (message.statistics.statistics.ipv6 || 0),
                        y: message.statistics.statistics.ipv6 || 0
                    }
                ]
            })
        } else if (message.action === "info") {
            notification.info({
                message: "来自服务器的提示",
                description: decrypt(message.info),
                duration: null
            })
        } else if (message.action === "error") {
            notification.error({
                message: "来自服务器的错误",
                description: decrypt(message.error) || "Unknown Error",
                duration: null
            })
        } else {
            console.log(message)
        }
    };

    startCapture = () => {
        this.capture_filter = this.capture_filter || "";
        this.sendCommand("start_capture", {
            index: this.capture_index,
            filter: this.capture_filter
        })
    };

    sendCommand = (command, extra) => {
        this.ws.send(JSON.stringify({
            action: "command",
            data: encrypt(JSON.stringify({
                command, extra
            }))
        }))
    };

    initWebSocket = (reconnect) => {
        const ws_url = (window.location.protocol.indexOf("s") > -1 ? "wss://" : "ws://")
            + window.location.host + "/websocket/";
        // const ws_url = "ws://" + window.location.hostname + ":12611/websocket/";
        this.ws = new WebSocket(ws_url);
        this.ws.onerror = event => {
            if (!reconnect && this.ws.readyState !== 1) {
                this.setState({
                    waiting: false,
                    error: "无法连接到服务器"
                })
            }
        };
        this.ws.onopen = () => {
            this.setState({
                error: null
            });
            this.ws_notification = true;
            if (reconnect) {
                notification.success({
                    message: "已重新连接",
                    description: "已成功重新连接到服务器",
                    duration: null,
                });
                this.ws_notification = true
            }
        };
        this.ws.onclose = () => {
            if (this.ws_notification) {
                notification.error({
                    message: "连接已断开",
                    description: "与服务器的连接中断，无法获取新数据",
                    duration: null,
                    onClose: () => this.ws_notification = true
                });
            }
            this.ws_notification = false;
            setTimeout(() => {
                this.initWebSocket(true)
            }, 1000)
        };
        this.ws.onmessage = this.onMessage;
    };

    componentDidMount() {
        this.initWebSocket(false)
    }

    componentWillUnmount() {
        if (this.ws) {
            this.ws.onclose = null;
            this.ws.close()
        }
    }

    render() {
        let content = null;
        if (this.state.waiting) {
            content = <div style={{ textAlign: 'center', marginTop: 10 }}>
                <Spin/>&nbsp;&nbsp;&nbsp;正在连接服务器
            </div>
        }
        else if (this.state.error) {
            content = <div style={{ textAlign: 'center', marginTop: 10, color: 'red' }}>
                <Icon type="exclamation-circle" />&nbsp;&nbsp;&nbsp;{this.state.error}
            </div>
        }
        let chartHeight = window.innerWidth * 0.25;
        if (window.innerWidth < 576)
            chartHeight *= 2;
        const statisticsTitle = this.state.statisticsUpdateTime ?
            "统计数据 （更新时间：" + this.state.statisticsUpdateTime + "）" : "统计数据";
        const capture_status = this.state.running === null ? "正在获取状态" : (
            this.state.running ? "正在捕获" : "未开始捕获"
        );
        const capture_filter = this.state.filter === null ? "未知过滤器" : this.state.filter || "无";
        return <Layout>
            <HeaderLayout text="实时捕获" />
            <Layout.Content>
                {
                    content ? content : <div>
                        <Collapse defaultActiveKey={['2']}>
                            <Collapse.Panel header={"捕获信息" +
                                (!this.state.filter ? "" : " - filter='" + capture_filter + "'")} key="1">
                                <h3>当前状态</h3>
                                <p>{capture_status}</p>
                                <h3>网卡信息</h3>
                                {
                                    this.state.running === true && this.state.interface ? <div style={{
                                        marginBottom: '.5em', lineHeight: 1.8
                                    }}>
                                        <div>Name: {this.state.interface.name}</div>
                                        <div>Description: {this.state.interface.description}</div>
                                        <div>IP Addresses:</div>
                                        {
                                            this.state.interface.addresses.map((address,i) => <div key={i}>
                                                &nbsp;&nbsp;&nbsp;&nbsp;{address}
                                            </div>)
                                        }
                                    </div> : <p>未知网卡</p>
                                }
                                <h3>过滤器</h3>
                                <p>{capture_filter}</p>
                                <h3>开始时间</h3>
                                <div>
                                    {
                                        this.state.running === true && this.state.statistics ?
                                            formatDate(new Date(this.state.statistics.startTime),
                                                "yyyy-MM-dd hh:mm:ss.S") : "未开始"
                                    }
                                </div>
                            </Collapse.Panel>
                            <Collapse.Panel header={"捕获控制 - " + capture_status} key="2">
                                {
                                    this.state.running === false && <div>
                                        <h3>网卡选择&nbsp;&nbsp;
                                            <Icon type="sync"
                                                  style={{
                                                      color: '#00A9FB',
                                                      cursor: 'pointer'
                                                  }}
                                                  onClick={() => {
                                                this.setState({
                                                    interfaces: null
                                                }, () => { this.sendCommand("list_interfaces") })
                                            }
                                        } /></h3>
                                        <Radio.Group defaultValue={0} buttonStyle="solid"
                                                     onChange={e => {
                                                         this.capture_index = e.target.value
                                                     }}>
                                            {
                                                this.state.interfaces &&
                                                this.state.interfaces.map((inter, i) => <Radio.Button value={i} key={i}>
                                                    <div>
                                                        <div>Name: {inter.name}</div>
                                                        <div>Description: {inter.description}</div>
                                                        <div>IP Addresses:</div>
                                                        {
                                                            inter.addresses.map((address,i) => <div key={i}>
                                                                &nbsp;&nbsp;&nbsp;&nbsp;{address}
                                                            </div>)
                                                        }
                                                    </div>
                                                </Radio.Button>)
                                            }
                                        </Radio.Group>
                                        <h3>可选过滤器</h3>
                                        <Input defaultValue={this.capture_filter} onChange={e => {
                                            this.capture_filter = e.target.value
                                        }} style={{ marginBottom: 15 }} />
                                        <Button type="primary" onClick={this.startCapture}>开始捕获</Button>
                                    </div>
                                }
                                {
                                    this.state.running === true && <div>
                                        <Button type="primary" onClick={
                                            () => this.sendCommand("stop_capture")
                                        }>停止捕获</Button>
                                    </div>
                                }
                            </Collapse.Panel>
                            <Collapse.Panel header={ statisticsTitle } key="3">
                                {
                                    this.state.statistics ? <Row>
                                        <Col xs={24} xl={12} style={{ padding: 50 }}>
                                            <Pie ref="pie" /*key={this.state._typeKey}*/
                                                hasLegend
                                                title="报文类别统计"
                                                subTitle="报文总数"
                                                total={() => (
                                                    <span>{this.state.statistics.totalCount}</span>
                                                )}
                                                data={this.state._type}
                                                valueFormat={value => <span>{value}</span>}
                                                height={chartHeight}
                                            />
                                        </Col>
                                        <Col xs={24} xl={12}>
                                            <ChartCard
                                                title="IP报文分布"
                                                total={this.state.statistics.statistics.ip}
                                                contentHeight={chartHeight}
                                            >
                                                <Bar height={chartHeight} data={this.state._ip} />
                                            </ChartCard>
                                        </Col>
                                    </Row> : null
                                }
                            </Collapse.Panel>
                        </Collapse>

                        <h3 style={{
                            margin: '25px 0 20px', fontSize: '18px', textAlign: 'center'
                        }}>捕获数据 - 只显示新增数据</h3>
                        <Table dataSource={this.state.data}
                               onRow={
                                   (record, index) => {
                                       return {
                                           onClick: () => {
                                               this.setState({
                                                   detail: record
                                               })
                                           }
                                       }
                                   }
                               }
                               size="small"
                               pagination={{ pageSize: 15 }}
                        >
                            <Column
                                title="Time"
                                dataIndex="time"
                                key="time"
                                width="20%"
                            />
                            <Column
                                title="类型"
                                dataIndex="type"
                                key="type"
                                width="15%"
                                // 类型筛选
                                filters={[
                                    { text: "TCP", value: "TCP" },
                                    { text: "UDP", value: "UDP" },
                                    { text: "ARP", value: "ARP" },
                                    { text: "ICMP", value: "ICMP" },
                                ]}
                                onFilter={
                                    (value, record) => record.type.startsWith(value)
                                }
                            />
                            <Column
                                title="Source"
                                dataIndex="src"
                                key="src"
                                width="25%"
                            />
                            <Column
                                title="Destination"
                                dataIndex="dst"
                                key="dst"
                                width="25%"
                            />
                            <Column
                                title="长度"
                                dataIndex="packet.length"
                                key="packet.length"
                                width="15%"
                            />
                        </Table>
                    </div>
                }
                <Drawer
                    title="报文详情"
                    placement="right"
                    closable={false}
                    onClose={() => this.setState({ detail: null })}
                    visible={this.state.detail !== null}
                >
                    <Tree>
                        { this.state.detail ? PacketTree(this.state.detail.packet) : null }
                    </Tree>
                </Drawer>
            </Layout.Content>
            <FooterLayout />
        </Layout>
    }
}

export default CapturePage;