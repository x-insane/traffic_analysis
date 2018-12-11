import React from "react";
import {Button, Checkbox, Col, Icon, Layout, List, Popconfirm, Row, Spin, Upload, message, Input} from "antd";
import HeaderLayout from "../layout/HeaderLayout";
import FooterLayout from "../layout/FooterLayout";
import Socket from "./components/Socket";

import {encrypt, decrypt, resetKey} from "../common/Crypto";
import PacketStatistics from "./components/PacketStatistics";
import PacketDataTable from "./components/PacketDataTable";

const Search = Input.Search;

const bytesToSize = bytes => {
    if (bytes === 0)
        return '0 B';
    let k = 1024;
    let sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    let i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
};

class PacketFilePage extends React.Component {

    state = {
        waiting: true,
        key_wrong: false,
        key: "",
        error: null,
        files: [],
        checkedFiles: [],
        openedFile: null,
        filter: ""
    };

    pageSize = 50;

    refreshFileList = () => {
        this.setState({
            files: [],
            checkedFiles: []
        });
        this.socket.requestFileList()
    };

    deleteCheckedFiles = () => {
        this.socket.deleteFiles(this.state.checkedFiles);
        this.setState({
            checkedFiles: []
        })
    };

    bindFile = (filename, filter) => {
        this.socket.bindFile(filename, filter);
        // if (this.refs.dataTable)
        //     this.refs.dataTable.clear();
        this.setState({
            openedFile: filename,
            filter: filter || ""
        })
    };

    onConnected = () => {
        this.refreshFileList();
        this.setState({
            waiting: false,
            key_wrong: false,
            error: null
        })
    };

    onReconnected = () => {
        this.refreshFileList()
    };

    onKeyWrong = () => {
        this.setState({
            key_wrong: true
        })
    };

    onSocketError = error => {
        this.setState({
            waiting: false,
            error: error
        })
    };

    onStatistics = (statistics, statisticsUpdateTime, typeStatistics, ipStatistics) => {
        if (this.refs.statistics)
            this.refs.statistics.update(statistics, typeStatistics, ipStatistics);
        if (this.refs.dataTable)
            this.refs.dataTable.fillToCount(statistics.totalCount);
    };

    onFileList = files => {
        this.setState({
            files
        })
    };

    onFileUploaded = response => {
        if (response.error === 0) {
            let data = JSON.parse(decrypt(response.data));
            data.forEach(item => {
                if (item.accept)
                    message.success("文件已成功上传到 " + item.save_name);
                else
                    message.error("文件 " + item.name + " 上传失败：" + item.reject_reason);
            });
            this.refreshFileList()
        } else {
            message.error(decrypt(response.msg))
        }
    };

    onOrderedPacket = (packet, position) => {
        if (this.refs.dataTable)
            this.refs.dataTable.onOrderedPacket(packet, position)
    };

    onPageChange = index => {
        if (this.refs.dataTable) {
            let start = (index - 1) * this.pageSize;
            if (!this.refs.dataTable.state.data[start]) {
                let number = Math.min(this.pageSize, this.refs.dataTable.count - start);
                let max_number = Math.min(this.pageSize * 10, this.refs.dataTable.count - start);
                while (number < max_number && !this.refs.dataTable.state.data[start+number])
                    number ++;
                this.socket.requestOrderedPackets(start, number)
            }
        }
    };

    init = key => {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
        if (key)
            resetKey(key);
        this.socket = new Socket({
            type: "file",
            onConnected: this.onConnected,
            onKeyWrong: this.onKeyWrong,
            onSocketError: this.onSocketError,
            onStatistics: this.onStatistics,
            onFileList: this.onFileList,
            onReconnected: this.onReconnected,
            onOrderedPacket: this.onOrderedPacket
        })
    };

    componentDidMount() {
        this.init()
    }

    componentWillUnmount() {
        if (this.socket)
            this.socket.close()
    }

    static wrapContent(content) {
        return <Layout>
            <HeaderLayout text="文件管理" />
            <Layout.Content>
                { content }
            </Layout.Content>
            <FooterLayout/>
        </Layout>
    }

    inputKeyNode() {
        return <div>
            <div style={{
                textAlign: 'center',
                marginTop: 10,
                marginBottom: 20,
                color: 'red'
            }}>
                <Icon type="exclamation-circle"/>&nbsp;&nbsp;&nbsp;请输入正确的密钥
            </div>
            <Search
                placeholder="16进制密钥"
                enterButton="验证"
                value={this.state.key}
                onChange={e => {
                    this.setState({
                        key: e.target.value
                    })
                }}
                style={{
                    maxWidth:'80%',
                    margin: '0 auto',
                    display: 'block'
                }}
                onSearch={key => {
                    this.setState({
                        key: ""
                    });
                    this.init(key)
                }}
            />
        </div>
    }

    render() {
        if (this.state.key_wrong)
            return PacketFilePage.wrapContent(this.inputKeyNode());
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
        const listNode = <List
            header={<div className="file-list-header">
                <span className="title">文件列表</span>
                <span className="action" onClick={this.refreshFileList}>刷新</span>
                <Popconfirm placement="bottom"
                            title={"确认删除这 " + this.state.checkedFiles.length + " 项吗？"}
                            okText="确定"
                            cancelText="取消"
                            onConfirm={this.deleteCheckedFiles}>
                    {
                        this.state.checkedFiles.length > 0 &&
                        <span className="action">删除</span>
                    }
                </Popconfirm>
            </div>}
            footer={<Upload name="file"
                            action="/upload"
                            accept=".pcap,application/vnd.tcpdump.pcap"
                            onChange={info => {
                                if (info.file.status === 'done')
                                    this.onFileUploaded(info.file.response);
                                else if (info.file.status === 'error')
                                    message.error("上传失败");
                            }
                            }>
                <Button>
                    <Icon type="upload"/> 上传
                </Button>
            </Upload>}
            bordered
            dataSource={this.state.files}
            pagination={{
                pageSize: 12,
                onChange: () => this.setState({checkedFiles: []})
            }}
            renderItem={item => (<List.Item>
                <Row style={{width: '100%'}}>
                    <Col span={14}>
                        <Checkbox key={item.name} onChange={e => {
                            if (e.target.checked) {
                                this.setState({
                                    checkedFiles: [...this.state.checkedFiles, item.name]
                                });
                            } else {
                                this.setState({
                                    checkedFiles: this.state.checkedFiles.filter(e => e !== item.name)
                                })
                            }
                        }}>{item.name}</Checkbox>

                    </Col>
                    <Col span={10}>
                        <div style={{textAlign: 'right'}}>
                            <span>{bytesToSize(item.size)}</span>
                            <div style={{
                                width: 40,
                                display: 'inline-block'
                            }}>
                                <span onClick={() => this.bindFile(item.name)} style={{
                                    color: '#1890ff',
                                    cursor: 'pointer'
                                }}>打开</span>
                            </div>
                            <div style={{
                                width: 35,
                                display: 'inline-block'
                            }}>
                                <a rel="noopener noreferrer" target="_blank"
                                   href={"/download/" + item.name + "?auth=" + encrypt(item.name)}>下载</a>
                            </div>
                        </div>
                    </Col>
                </Row>
            </List.Item>)}
        />;
        return PacketFilePage.wrapContent(waitingMessage || <div>
        {
            !this.state.openedFile ? listNode : <div>
                <p><Button style={{
                    marginLeft: window.innerWidth < 768 ? 15 : 0,
                    marginTop: window.innerWidth < 768 ? 15 : 0
                }} onClick={() => {
                    this.socket.unbindFile();
                    this.setState({
                        openedFile: null
                    })
                }}>关闭</Button></p>
                <p className="filter-button" style={{
                    marginLeft: window.innerWidth < 768 ? 15 : 0,
                    marginRight: window.innerWidth < 768 ? 15 : 0,
                    marginBottom: 15
                }}><Search
                    placeholder="filter"
                    enterButton="筛选"
                    onSearch={filter => {
                        this.bindFile(this.state.openedFile, filter)
                    }}
                /></p>
                <PacketStatistics ref="statistics"/>
                <h3 style={{
                    margin: '25px 0 20px', fontSize: '18px', textAlign: 'center'
                }}>数据列表</h3>
                <PacketDataTable ref="dataTable"
                                 key={this.state.openedFile + "-" + this.state.filter}
                                 filter={false}
                                 onPageChange={this.onPageChange}
                                 pageSize={this.pageSize}/>
            </div>
        }
        </div>)
    }
}

export default PacketFilePage;