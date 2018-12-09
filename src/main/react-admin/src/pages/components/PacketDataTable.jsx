import React from "react";
import { Drawer, Table, Tree } from "antd";
import PacketTree from "./PacketTree";

const { Column } = Table;

class PacketDataTable extends React.Component {

    state = {
        data: [],
        detail: null,
    };

    maxCache = 1000;
    count = 0;
    loadedCount = 0;
    timer = null;
    pageSize = 15;
    page = 1;

    componentDidMount() {
        if (this.props.pageSize)
            this.pageSize = this.props.pageSize
    }

    componentWillUnmount() {
        if (this.timer)
            clearTimeout(this.timer)
    }

    onPacket = item => {
        item.key = this.count ++;
        this.state.data.push(item);
        if (this.count >= this.maxCache)
            delete this.state.data[this.count - this.maxCache];
        if (!this.timer) {
            this.timer = setTimeout(() => {
                this.forceUpdate();
                this.timer = null
            }, 1000)
        }
    };

    fillToCount = count => {
        this.list = this.state.data;
        const realCount = Math.max(this.count, count);
        if (count > this.pageSize) {
            while (this.count < count) {
                this.list[this.count] = null;
                delete this.list[this.count++]
            }
        }
        this.count = realCount;
        this.setState({
            data: this.list
        })
    };

    // clear = () => {
    //     if (this.timer)
    //         clearTimeout(this.timer);
    //     this.timer = null;
    //     this.count = 0;
    //     this.loadedCount = 0;
    //     this.setState({
    //         data: [],
    //         detail: null,
    //     })
    // };

    onOrderedPacket = (item, index) => {
        item.key = index;
        this.list = this.state.data;
        if (!this.list[index]) {
            this.list[index] = item;
            this.loadedCount ++;
        }
        if (this.loadedCount > this.maxCache) {
            let deletePage = 1;
            while (deletePage === this.page || !this.state.data[deletePage])
                deletePage ++;
            deletePage --;
            for (let i = 0; i < this.pageSize; ++i)
                delete this.state.data[deletePage * this.pageSize + i];
        }
        if (!this.timer) {
            this.timer = setTimeout(() => {
                this.setState({
                    data: this.list
                });
                // console.log(this.loadedCount);
                this.timer = null
            }, 1000)
        }
    };

    render() {
        const filter = this.props.filter === false ? {} : {
            filters: [
                { text: "TCP", value: "TCP" },
                { text: "UDP", value: "UDP" },
                { text: "ARP", value: "ARP" },
                { text: "ICMP", value: "ICMP" },
            ],
            onFilter: (value, record) => record.type.startsWith(value)
        };
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
                   pagination={{
                       pageSize: this.pageSize,
                       onChange: index => {
                           this.page = index;
                           if (this.props.onPageChange)
                               this.props.onPageChange(index)
                       },
                       showQuickJumper: true
                   }}
            >
                <Column
                    title="Time/ID"
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
                    {...filter}
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