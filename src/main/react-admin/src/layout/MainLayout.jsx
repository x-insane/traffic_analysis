import React, { Component } from 'react';

import { Link, Switch, Redirect, Route, withRouter } from 'react-router-dom';
import { Layout, Menu, Icon } from 'antd';
import CapturePage from "../pages/CapturePage";
import PacketPage from "../pages/PacketPage";

class MainLayout extends Component {
    state = {
        collapsed: true
    };

    onCollapse = (collapsed) => {
        this.setState({ collapsed })
    };

    coverClick = () => {
        if (window.innerWidth <= 768) {
            this.setState({
                collapsed: true
            })
        }
    };

    Cover = () => <div className="page-side-cover" onClick={this.coverClick} />;

    componentWillMount() {
        if (window.innerWidth > 768) {
            this.setState({
                collapsed: false
            })
        }
    }

    render() {
        return (
            <Layout style={{ minHeight: '100vh' }}>
                <Layout.Sider
                    collapsible
                    collapsed={this.state.collapsed}
                    onCollapse={this.onCollapse}
                    breakpoint="md"
                    collapsedWidth={0}
                >

                    <Menu theme="dark" defaultSelectedKeys={[
                        this.props.location.pathname === "/packet" ? "/packet" : "/capture"
                    ]} mode="inline" onClick={this.coverClick}>

                        <Menu.Item key="/capture">
                            <Icon type="user" theme="outlined" />
                            <span>实时捕获</span>
                            <Link to="/capture" />
                        </Menu.Item>

                        <Menu.Item key="/packet">
                            <Icon type="dashboard" theme="outlined" />
                            <span>文件管理</span>
                            <Link to="/packet" />
                        </Menu.Item>

                    </Menu>
                </Layout.Sider>

                { this.state.collapsed ? "" : <this.Cover /> }

                <Switch>
                    <Route path="/capture" component={CapturePage}/>
                    <Route path="/packet" component={PacketPage}/>
                    <Route path='/' render={() => <Redirect to="/capture"/>}/>
                </Switch>

            </Layout>
        );
    }
}

export default withRouter(MainLayout);
