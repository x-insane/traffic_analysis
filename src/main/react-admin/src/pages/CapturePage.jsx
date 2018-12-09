import React from "react";
import { Collapse, Icon, Layout, Spin, Radio, Button, Input } from "antd";
import HeaderLayout from "../layout/HeaderLayout";
import FooterLayout from "../layout/FooterLayout";
import formatDate from '../common/FormatDate.js';
import PacketDataTable from "./components/PacketDataTable";
import Socket from "./components/Socket";
import PacketStatistics from "./components/PacketStatistics";

class CapturePage extends React.Component {

    state = {
        waiting: true,
        error: null,
        running: null,
        statisticsUpdateTime: null,
        interfaces: null,
        interface: null,
        filter: null,
        start_time: null
    };

    capture_index = 0;
    statistics_timer = null;

    startCapture = () => {
        this.socket.startCapture(this.capture_index, this.state.filter)
    };

    onConnected = () => {
        this.socket.requestCaptureStatus();
        this.setState({
            waiting: false,
            error: null
        })
    };

    onSocketError = error => {
        this.setState({
            waiting: false,
            error: error
        })
    };

    onCaptureStatus = (status, callback) => {
        if (status.running) {
            this.setState({
                running: status.running,
                interface: status.interface,
                filter: status.filter
            }, callback)
        }
        else {
            this.setState({
                running: status.running,
                filter: null,
                statisticsUpdateTime: null
            }, callback)
        }
    };

    onInterfaces = interfaces => {
        this.setState({
            interfaces: interfaces,
            running: false
        })
    };

    onStatistics = (statistics, statisticsUpdateTime, typeStatistics, ipStatistics) => {
        if (this.statistics_timer === null) {
            this.statistics_timer = setTimeout(() => {
                this.socket.requestStatistics();
                this.statistics_timer = null
            }, 5000)
        }
        this.setState({
            statisticsUpdateTime
        });
        if (this.refs.statistics)
            this.refs.statistics.update(statistics, typeStatistics, ipStatistics)
    };

    onPacket = item => {
        if (this.refs.dataTable)
            this.refs.dataTable.onPacket(item)
    };

    componentDidMount() {
        this.socket = new Socket({
            type: "capture",
            onConnected: this.onConnected,
            onSocketError: this.onSocketError,
            onCaptureStatus: this.onCaptureStatus,
            onInterfaces: this.onInterfaces,
            onStatistics: this.onStatistics,
            onPacket: this.onPacket
        })
    }

    componentWillUnmount() {
        if (this.socket)
            this.socket.close();
        if (this.statistics_timer)
            clearTimeout(this.statistics_timer)
    }

    render() {
        let waitingMessage = null;
        if (this.state.waiting) {
            waitingMessage = <div style={{ textAlign: 'center', marginTop: 10 }}>
                <Spin/>&nbsp;&nbsp;&nbsp;正在连接服务器
            </div>
        }
        else if (this.state.error) {
            waitingMessage = <div style={{ textAlign: 'center', marginTop: 10, color: 'red' }}>
                <Icon type="exclamation-circle" />&nbsp;&nbsp;&nbsp;{this.state.error}
            </div>
        }
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
                    waitingMessage ? waitingMessage : <div>
                        <Collapse defaultActiveKey={['2']} onChange={ e => {
                            if (e.indexOf("3") > -1)
                                setTimeout(this.socket.requestStatistics, 500)
                        }}>
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
                                                }, this.socket.listInterfaces )
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
                                        <Input defaultValue={this.state.filter} onChange={e => {
                                            this.setState({
                                                filter: e.target.value
                                            })
                                        }} style={{ marginBottom: 15 }} />
                                        <Button type="primary" onClick={this.startCapture}>开始捕获</Button>
                                    </div>
                                }
                                {
                                    this.state.running === true && <div>
                                        <Button type="primary" onClick={this.socket.stopCapture}>停止捕获</Button>
                                    </div>
                                }
                            </Collapse.Panel>
                            <Collapse.Panel header={ statisticsTitle } key="3">
                                <PacketStatistics ref="statistics" />
                            </Collapse.Panel>
                        </Collapse>

                        <h3 style={{
                            margin: '25px 0 20px', fontSize: '18px', textAlign: 'center'
                        }}>捕获数据 - 只显示新增数据</h3>
                        <PacketDataTable ref="dataTable" />
                    </div>
                }
            </Layout.Content>
            <FooterLayout />
        </Layout>
    }
}

export default CapturePage;