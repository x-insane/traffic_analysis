import React from 'react';
import 'antd/dist/antd.css';
import 'ant-design-pro/dist/ant-design-pro.css';
import './App.css';

import { HashRouter as Router } from 'react-router-dom';
import MainLayout from "./layout/MainLayout";

const App = () => <Router>
    <MainLayout/>
</Router>;

export default App;
