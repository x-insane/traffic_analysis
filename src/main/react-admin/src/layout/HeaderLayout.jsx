import React from "react";
import { Layout } from "antd";

const header = props => <Layout.Header style={{ background: '#fff'}}>
    {
        props.text ? <h2>{props.text}</h2> : null
    }
    { props.children }
</Layout.Header>;

export default header;

