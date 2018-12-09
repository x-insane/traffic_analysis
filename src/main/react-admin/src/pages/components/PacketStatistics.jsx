import React from "react";
import { Col, Row } from "antd";
import { Charts } from "ant-design-pro";

const { ChartCard, Bar, Pie } = Charts;

class PacketStatistics extends React.Component {

    state = {
        statistics: {
            totalCount: 0,
            statistics: {
                ip: 0
            }
        },
        typeStatistics: [],
        ipStatistics: [
            { x: "IPv4", y: 0 },
            { x: "IPv6", y: 0 }
        ],
    };

    update = (statistics, typeStatistics, ipStatistics) => {
        if (!this.update_timer) {
            this.update_timer = setTimeout(() => {
                this.setState(this.updated);
                this.update_timer = null
            }, 500)
        }
        this.updated = {
            statistics,
            typeStatistics,
            ipStatistics
        };
        this.resize()
    };

    resize = () => {
        // 修复饼图大小绘制错误
        // console.log(this.hasResize);
        if (!this.hasResize) {
            this.hasResize = true;
            setTimeout(() => {
                if (typeof(Event) === 'function') {
                    // modern browsers
                    window.dispatchEvent(new Event('resize'));
                } else {
                    // for IE and other old browsers
                    // causes deprecation warning on modern browsers
                    var evt = window.document.createEvent('UIEvents');
                    evt.initUIEvent('resize', true,
                        false, window, 0);
                    window.dispatchEvent(evt);
                }
            }, 500)
        }
    };

    render() {
        let chartHeight = window.innerWidth * 0.25;
        if (window.innerWidth < 576)
            chartHeight *= 2;
        return <Row>
            <Col xs={24} xl={12} style={{ padding: 50 }}>
                <Pie ref="pie" /*key={this.state._typeKey}*/
                     hasLegend
                     title="报文类别统计"
                     subTitle="报文总数"
                     total={() => (
                         <span>{this.state.statistics.totalCount}</span>
                     )}
                     data={this.state.typeStatistics}
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
                    <Bar height={chartHeight} data={this.state.ipStatistics} />
                </ChartCard>
            </Col>
        </Row>
    }
}

export default PacketStatistics;