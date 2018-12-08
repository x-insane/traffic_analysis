import React from "react";
import { Drawer, Table, Tree } from "antd";
import PacketTree from "./PacketTree";

const { Column } = Table;

class PacketDataTable extends React.Component {

    state = {
        data: [],
        detail: null,
    };

    count = 0;
    timer = null;

    onPacket = item => {
        item.key = this.count ++;
        this.state.data.push(item);
        if (this.count >= 10000)
            delete this.state.data[this.count-10000];
        if (!this.timer) {
            this.timer = setTimeout(() => {
                this.forceUpdate();
                this.timer = null
            }, 1000)
        }
    };

    render() {
        return <div>
            <Table dataSource={this.state.data}
                   onRow={
                       record => {
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
        </div>
    }
}

export default PacketDataTable;