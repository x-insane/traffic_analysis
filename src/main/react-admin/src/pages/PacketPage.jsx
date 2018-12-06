import React from "react";
import { Layout } from "antd";
import HeaderLayout from "../layout/HeaderLayout";
import FooterLayout from "../layout/FooterLayout";

class PacketPage extends React.Component {
    render() {
        return <Layout>
            <HeaderLayout text="文件管理" />
            <Layout.Content>
            </Layout.Content>
            <FooterLayout />
        </Layout>
    }
}

export default PacketPage;