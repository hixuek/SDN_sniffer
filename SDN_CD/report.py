#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN匹配域嗅探攻击平台 - 报告生成器
负责生成实验报告和安全分析
"""

import logging
import json
import os
import time
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
from jinja2 import Template

logger = logging.getLogger(__name__)

class ReportGenerator:
    """报告生成器"""
    
    def __init__(self):
        # 确保导出目录存在
        os.makedirs('exports', exist_ok=True)
        
        # HTML报告模板
        self.html_template = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SDN匹配域嗅探攻击安全分析报告</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;700&display=swap');
        body {
            font-family: 'Noto Sans SC', 'Microsoft YaHei', '微软雅黑', 'PingFang SC', 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
            font-weight: 500;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px 15px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #4a89dc;
            color: white;
            font-weight: 500;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .chart {
            margin: 20px 0;
            text-align: center;
        }
        .chart img {
            max-width: 100%;
            height: auto;
        }
        .risk-high {
            color: #e74c3c;
            font-weight: 500;
        }
        .risk-medium {
            color: #f39c12;
            font-weight: 500;
        }
        .risk-low {
            color: #27ae60;
            font-weight: 500;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>SDN匹配域嗅探攻击安全分析报告</h1>
        <p>生成时间: {{ timestamp }}</p>
    </div>
    
    <div class="section">
        <h2>1. 实验概述</h2>
        <p>本实验模拟了针对SDN网络的匹配域嗅探攻击，通过测量不同匹配域的RTT差异，推断SDN交换机中的流表匹配规则。</p>
        <p>实验使用了2个OpenFlow交换机和4个主机组成的拓扑结构，通过发送特制探测包并测量RTT来检测匹配域的可识别性。</p>
    </div>
    
    <div class="section">
        <h2>2. 网络拓扑</h2>
        <h3>交换机信息:</h3>
        <table>
            <tr>
                <th>名称</th>
                <th>DPID</th>
                <th>流表规则</th>
            </tr>
            {% for switch in topology.switches %}
            <tr>
                <td>{{ switch.name }}</td>
                <td>{{ switch.dpid }}</td>
                <td>{{ switch.flow_rule }}</td>
            </tr>
            {% endfor %}
        </table>
        
        <h3>主机信息:</h3>
        <table>
            <tr>
                <th>名称</th>
                <th>IP地址</th>
                <th>MAC地址</th>
            </tr>
            {% for host in topology.hosts %}
            <tr>
                <td>{{ host.name }}</td>
                <td>{{ host.ip }}</td>
                <td>{{ host.mac }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h2>3. 攻击配置</h2>
        <table>
            <tr>
                <th>参数</th>
                <th>值</th>
            </tr>
            <tr>
                <td>源IP地址</td>
                <td>{{ attack_config.srcIP }}</td>
            </tr>
            <tr>
                <td>目标IP地址</td>
                <td>{{ attack_config.dstIP }}</td>
            </tr>
            <tr>
                <td>数据包数量</td>
                <td>{{ attack_config.packetCount }}</td>
            </tr>
            <tr>
                <td>发送间隔</td>
                <td>{{ attack_config.interval }}ms</td>
            </tr>
            <tr>
                <td>测试匹配域</td>
                <td>{{ attack_config.fields|join(', ') }}</td>
            </tr>
        </table>
    </div>
    
    <div class="section">
        <h2>4. 测量结果</h2>
        <div class="chart">
            <img src="data:image/png;base64,{{ chart_base64 }}" alt="RTT测量结果图表">
        </div>
        
        <h3>详细数据:</h3>
        <table>
            <tr>
                <th>匹配域</th>
                <th>平均RTT(ms)</th>
                <th>最小RTT(ms)</th>
                <th>最大RTT(ms)</th>
                <th>方差</th>
            </tr>
            {% for field, data in results.items() %}
            <tr>
                <td>{{ field }}</td>
                <td>{{ "%.2f"|format(data.avgRTT) }}</td>
                <td>{{ "%.2f"|format(data.minRTT) }}</td>
                <td>{{ "%.2f"|format(data.maxRTT) }}</td>
                <td>{{ "%.2f"|format(data.variance) }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h2>5. 安全分析</h2>
        
        <h3>风险评估:</h3>
        <p class="risk-{{ risk_level|lower }}">风险等级: {{ risk_level }}</p>
        <p>{{ risk_description }}</p>
        
        <h3>检测到的可识别匹配域:</h3>
        <ul>
            {% for field in detected_fields %}
            <li>{{ field }} (方差: {{ "%.2f"|format(results[field].variance) }}ms)</li>
            {% endfor %}
        </ul>
        
        <h3>安全建议:</h3>
        <ol>
            {% for recommendation in recommendations %}
            <li>{{ recommendation }}</li>
            {% endfor %}
        </ol>
    </div>
    
    <div class="footer">
        <p>软件定义网络课程设计 | 薛康2200170151 | 王才凤2200170236</p>
        <p>生成时间: {{ timestamp }}</p>
    </div>
</body>
</html>
"""
    
    def generate_full_report(self, topology_info, attack_config, results, format='json'):
        """
        生成完整的安全分析报告
        
        参数:
            topology_info: 拓扑信息字典
            attack_config: 攻击配置字典
            results: 攻击结果字典
            format: 报告格式 (json, html)
            
        返回:
            报告内容字符串
        """
        try:
            logger.info(f"生成{format}格式报告...")
            
            # 分析结果
            risk_level, risk_description, detected_fields, recommendations = self._analyze_results(results)
            
            # 生成报告数据
            report_data = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'topology': topology_info,
                'attack_config': attack_config,
                'results': results,
                'risk_level': risk_level,
                'risk_description': risk_description,
                'detected_fields': detected_fields,
                'recommendations': recommendations
            }
            
            # 根据格式生成报告
            if format.lower() == 'json':
                return json.dumps(report_data, indent=2, ensure_ascii=False)
            elif format.lower() == 'html':
                # 生成图表
                chart_base64 = self._generate_chart(results)
                
                # 渲染HTML模板
                template = Template(self.html_template)
                return template.render(
                    timestamp=report_data['timestamp'],
                    topology=report_data['topology'],
                    attack_config=report_data['attack_config'],
                    results=report_data['results'],
                    risk_level=risk_level,
                    risk_description=risk_description,
                    detected_fields=detected_fields,
                    recommendations=recommendations,
                    chart_base64=chart_base64
                )
            else:
                logger.error(f"不支持的报告格式: {format}")
                return json.dumps({"error": f"不支持的报告格式: {format}"})
                
        except Exception as e:
            logger.error(f"生成报告时发生错误: {str(e)}")
            return json.dumps({"error": f"生成报告失败: {str(e)}"})
    
    def _analyze_results(self, results):
        """分析攻击结果，评估安全风险"""
        # 检测可识别的匹配域
        detected_fields = []
        for field, data in results.items():
            # 方差大于阈值的字段被认为是可识别的
            if data['variance'] > 1.0:
                detected_fields.append(field)
        
        # 根据可识别匹配域数量评估风险
        if len(detected_fields) >= 3:
            risk_level = "HIGH"
            risk_description = "检测到多个匹配域存在显著的RTT差异，攻击者可以通过这些差异推断出SDN网络中的流表规则，存在严重的安全风险。"
        elif len(detected_fields) >= 1:
            risk_level = "MEDIUM"
            risk_description = "检测到部分匹配域存在RTT差异，攻击者可能通过这些差异获取部分流表信息，存在一定安全风险。"
        else:
            risk_level = "LOW"
            risk_description = "未检测到明显的匹配域RTT差异，当前流表配置相对安全。"
        
        # 安全建议
        recommendations = [
            "实施统一的数据包处理时间，减少不同匹配域之间的RTT差异",
            "添加随机延迟以混淆RTT模式，防止攻击者通过RTT差异推断流表规则",
            "监控网络中的异常探测行为，及时发现潜在的嗅探攻击",
            "限制单个源的探测频率，防止大量探测包导致的拒绝服务",
            "使用加密通道保护控制器与交换机之间的通信，防止流表信息泄露",
            "定期更新流表规则，减少攻击者推断的时间窗口"
        ]
        
        return risk_level, risk_description, detected_fields, recommendations
    
    def _generate_chart(self, results):
        """生成RTT测量结果图表，返回Base64编码的图像"""
        try:
            import io
            import base64
            import matplotlib
            matplotlib.use('Agg')  # 使用非交互式后端
            
            # 提取数据
            fields = list(results.keys())
            avg_rtts = [results[field]['avgRTT'] for field in fields]
            min_rtts = [results[field]['minRTT'] for field in fields]
            max_rtts = [results[field]['maxRTT'] for field in fields]
            
            # 创建图表
            plt.figure(figsize=(10, 6))
            x = np.arange(len(fields))
            width = 0.25
            
            plt.bar(x - width, min_rtts, width, label='最小RTT')
            plt.bar(x, avg_rtts, width, label='平均RTT')
            plt.bar(x + width, max_rtts, width, label='最大RTT')
            
            plt.xlabel('匹配域')
            plt.ylabel('RTT (ms)')
            plt.title('不同匹配域的RTT测量结果')
            plt.xticks(x, fields)
            plt.legend()
            plt.grid(True, linestyle='--', alpha=0.7)
            
            # 将图表转换为Base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=100)
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            plt.close()
            
            return image_base64
            
        except Exception as e:
            logger.error(f"生成图表时发生错误: {str(e)}")
            return ""
