#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN拓扑管理器
负责启动和管理Mininet拓扑以及Ryu控制器
作者: 薛康2200170151 | 王才凤2200170236
"""

import subprocess
import time
import logging
import requests
import json
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from functools import partial
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
import signal
import os
import sys
import atexit

logger = logging.getLogger(__name__)

class CustomTopology(Topo):
    """自定义SDN拓扑: 2交换机 + 4主机 + 1控制器"""
    
    def __init__(self):
        Topo.__init__(self)
        
        # 添加交换机
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
        
        # 添加主机
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02') 
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        
        # 添加链路
        # 主机连接到交换机
        self.addLink(h1, s1, cls=TCLink, bw=10)
        self.addLink(h2, s1, cls=TCLink, bw=10)
        self.addLink(h3, s2, cls=TCLink, bw=10)
        self.addLink(h4, s2, cls=TCLink, bw=10)
        
        # 交换机互联
        self.addLink(s1, s2, cls=TCLink, bw=10)

class TopologyManager:
    """拓扑管理器"""
    
    def __init__(self):
        self.net = None
        self.ryu_process = None
        self.controller_ip = '127.0.0.1'
        self.controller_port = 6653
        self.ryu_rest_port = 8081  # 修改为 8081，避免与 HTTP 服务器冲突
        
        # Ryu控制器应用路径
        self.ryu_app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ryu_app.py')
        logger.info(f"Ryu控制器应用路径: {self.ryu_app_path}")
        
        # 注册退出处理函数，确保程序退出时清理资源
        # atexit.register(self.cleanup)
    
    def check_port_in_use(self, port):
        """检查端口是否被占用"""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(('127.0.0.1', port))
            return False
        except socket.error:
            return True
        finally:
            s.close()
    
    def kill_process_on_port(self, port):
        """结束占用指定端口的进程"""
        try:
            # 使用 lsof 查找占用端口的进程
            cmd = f"lsof -i :{port} -t"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.stdout.strip():
                pid = result.stdout.strip()
                logger.info(f"发现进程 PID {pid} 占用端口 {port}，尝试结束该进程")
                # 结束进程
                kill_cmd = f"kill -9 {pid}"
                subprocess.run(kill_cmd, shell=True)
                time.sleep(1)  # 等待进程结束
                return True
            return False
        except Exception as e:
            logger.error(f"结束进程时发生错误: {str(e)}")
            return False
            
    def check_switch_connection(self, switch_name):
        """检查交换机是否连接到控制器"""
        try:
            if not self.net:
                logger.warning("网络尚未创建，无法检查交换机连接")
                return False
                
            # 获取交换机对象
            switch = self.net.get(switch_name)
            if not switch:
                logger.warning(f"找不到交换机 {switch_name}")
                return False
                
            # 检查交换机是否连接到控制器
            result = switch.cmd('ovs-vsctl show')
            if 'is_connected: true' in result:
                logger.info(f"交换机 {switch_name} 已连接到控制器")
                return True
            else:
                # 尝试使用另一种方法检查，指定 OpenFlow 1.3 协议
                dpid = switch.dpid
                result = switch.cmd(f'ovs-ofctl -O OpenFlow13 show {switch_name}')
                if 'OFPT_FEATURES_REPLY' in result:
                    logger.info(f"交换机 {switch_name} 已连接到控制器")
                    return True
                    
                logger.warning(f"交换机 {switch_name} 未连接到控制器")
                return False
                
        except Exception as e:
            logger.error(f"检查交换机连接时发生错误: {str(e)}")
            return False
    
    def start_ryu_controller(self):
        """从系统 Python 启动虚拟环境中的 Ryu 控制器"""
        try:
            if self.ryu_process and self.ryu_process.poll() is None:
                logger.info("Ryu控制器已在运行")
                return True
            
            # 检查 Ryu 控制器端口是否被占用
            if self.check_port_in_use(self.ryu_rest_port):
                logger.warning(f"Ryu REST API 端口 {self.ryu_rest_port} 已被占用，尝试清理")
                self.kill_process_on_port(self.ryu_rest_port)
            
            if self.check_port_in_use(self.controller_port):
                logger.warning(f"OpenFlow 控制器端口 {self.controller_port} 已被占用，尝试清理")
                self.kill_process_on_port(self.controller_port)
            
            # 使用 bash 脚本启动 Ryu 控制器
            # 创建一个临时脚本文件
            script_path = '/tmp/start_ryu.sh'
            with open(script_path, 'w') as f:
                f.write(f"#!/bin/bash\n")
                f.write(f"source /home/hoshino/env_py397/bin/activate\n")
                f.write(f"cd {os.path.dirname(self.ryu_app_path)}\n")
                f.write(f"exec ryu-manager {os.path.basename(self.ryu_app_path)} --verbose --observe-links \\\n")
                f.write(f"  --ofp-tcp-listen-port={self.controller_port} \\\n")
                f.write(f"  --wsapi-port={self.ryu_rest_port} \\\n")
                f.write(f"  2>> ryu.log\n")
            
            # 设置脚本文件权限
            os.chmod(script_path, 0o755)
            
            logger.info(f"启动Ryu控制器: {script_path}")
            
            # 启动Ryu控制器进程
            self.ryu_process = subprocess.Popen(
                ['/bin/bash', script_path],
                stdout=subprocess.DEVNULL,  # 不再捕获标准输出
                stderr=subprocess.DEVNULL,  # 不再捕获标准错误
                preexec_fn=os.setsid  # 创建新的进程组
            )
            
            # 等待控制器启动
            time.sleep(5)
            
            # 检查进程是否还在运行
            if self.ryu_process.poll() is None:
                logger.info("Ryu控制器启动成功")
                return True
            else:
                logger.error(f"Ryu控制器启动失败，请查看 ryu.log 文件了解详细信息")
                return False
                
        except Exception as e:
            logger.error(f"启动Ryu控制器时发生错误: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def stop_ryu_controller(self):
        """停止Ryu控制器"""
        if self.ryu_process and self.ryu_process.poll() is None:
            try:
                # 发送SIGTERM信号给进程组
                os.killpg(os.getpgid(self.ryu_process.pid), signal.SIGTERM)
                self.ryu_process.wait(timeout=3)
                logger.info("Ryu控制器已停止")
            except subprocess.TimeoutExpired:
                # 如果超时，发送SIGKILL
                os.killpg(os.getpgid(self.ryu_process.pid), signal.SIGKILL)
                logger.warning("Ryu控制器被强制终止")
            except Exception as e:
                logger.error(f"停止Ryu控制器时发生错误: {str(e)}")
            finally:
                self.ryu_process = None
                
    def cleanup(self):
        """清理资源，在程序退出时调用"""
        try:
            if self.net:
                logger.info("程序退出，清理Mininet网络...")
                self.net.stop()
                self.net = None
            
            if self.ryu_process and self.ryu_process.poll() is None:
                logger.info("程序退出，停止Ryu控制器...")
                self.stop_ryu_controller()
                
            # 清理Mininet残留
            subprocess.run(['sudo', 'mn', '-c'], capture_output=True)
        except Exception as e:
            logger.error(f"清理资源时发生错误: {str(e)}")
    
    def start_topology(self):
        """启动Mininet拓扑"""
        try:
            if self.net:
                logger.info("拓扑已在运行")
                return True
            
            logger.info("创建SDN拓扑...")
            
            # 设置日志级别
            setLogLevel('info')
            
            # 创建拓扑
            topo = CustomTopology()
            
            # 创建 OpenFlow 1.3 版本的 OVSSwitch
            OVSSwitch13 = partial(OVSSwitch, protocols='OpenFlow13')
            
            # 创建网络，指定远程控制器
            self.net = Mininet(
                topo=topo,
                controller=lambda name: RemoteController(
                    name, 
                    ip=self.controller_ip, 
                    port=self.controller_port
                ),
                switch=OVSSwitch13,
                link=TCLink,
                autoSetMacs=True,
                autoStaticArp=False,
                ipBase='10.0.0.0/8',
            )
            
            # 启动网络
            self.net.start()
            
            # 交换机已在 Mininet 初始化时通过 switchOpts 设置 OpenFlow 1.3
            # for switch in self.net.switches:
            #     switch.cmd(f'ovs-vsctl set bridge {switch.name} protocols=OpenFlow13')
            #     logger.info(f"设置交换机 {switch.name} 使用 OpenFlow 1.3 协议")
            
            # 等待控制器连接
            time.sleep(3)
            
            # 添加全通流表规则，确保主机间可以通信
            logger.info("为所有交换机添加全通流表规则 priority=0,actions=NORMAL")
            for switch in self.net.switches:
                cmd = f'ovs-ofctl -O OpenFlow13 add-flow {switch.name} "priority=0,actions=NORMAL"'
                result = switch.cmd(cmd)
                logger.info(f"[{switch.name}] 添加全通流表: {cmd}，结果: {result}")
            
            # 配置主机IP地址（确保正确配置）
            for host in self.net.hosts:
                logger.info(f"配置主机 {host.name}: IP={host.IP()}, MAC={host.MAC()}")
                
                # 确保主机网络接口已启用
                host.cmd('ifconfig lo up')
                host.cmd(f'ifconfig {host.name}-eth0 up')
                
                # 添加默认路由
                # host.cmd(f'route add default gw {host.IP().split(".")[0]}.{host.IP().split(".")[1]}.{host.IP().split(".")[2]}.1')
            
            # 检查交换机是否连接到控制器
            connection_ok = True
            for switch in self.net.switches:
                if not self.check_switch_connection(switch.name):
                    logger.warning(f"交换机 {switch.name} 未连接到控制器")
                    connection_ok = False
            
            if connection_ok:
                logger.info("拓扑创建成功，所有交换机已连接到控制器")
            else:
                logger.warning("拓扑创建成功，但控制器连接异常")
            
            return True
            
        except Exception as e:
            logger.error(f"创建拓扑时发生错误: {str(e)}")
            if self.net:
                self.net.stop()
                self.net = None
            return False
    
    def stop_topology(self):
        """停止拓扑"""
        try:
            if self.net:
                logger.info("停止Mininet网络...")
                self.net.stop()
                self.net = None
            
            # 停止Ryu控制器
            self.stop_ryu_controller()
            
            # 清理残留进程
            subprocess.run(['sudo', 'mn', '-c'], capture_output=True)
            
            logger.info("拓扑已停止")
            
        except Exception as e:
            logger.error(f"停止拓扑时发生错误: {str(e)}")
    
    def get_topology_info(self):
        """获取拓扑信息"""
        if not self.net:
            return {}
        
        try:
            info = {
                'switches': [],
                'hosts': [],
                'links': [],
                'controller': {
                    'ip': self.controller_ip,
                    'port': self.controller_port,
                    'rest_port': self.ryu_rest_port
                }
            }
            
            # 获取交换机信息
            for switch in self.net.switches:
                info['switches'].append({
                    'name': switch.name,
                    'dpid': switch.dpid,
                    'ip': switch.IP() if hasattr(switch, 'IP') else 'N/A'
                })
            
            # 获取主机信息
            for host in self.net.hosts:
                info['hosts'].append({
                    'name': host.name,
                    'ip': host.IP(),
                    'mac': host.MAC()
                })
            
            # 获取链路信息
            for link in self.net.links:
                info['links'].append({
                    'node1': link.intf1.node.name,
                    'node2': link.intf2.node.name,
                    'intf1': link.intf1.name,
                    'intf2': link.intf2.name
                })
            
            return info
            
        except Exception as e:
            logger.error(f"获取拓扑信息时发生错误: {str(e)}")
            return {}
    
    def configure_flows(self, flow_configs):
        """配置流表规则"""
        try:
            if not self.net:
                logger.error("拓扑未启动")
                return False
            
            success_count = 0
            
            for config in flow_configs:
                switch_name = config['switch']
                match = config['match']
                actions = config['actions']
                
                # 自动补全TCP端口匹配的前置条件
                if 'tp_src' in match or 'tp_dst' in match:
                    if 'dl_type' not in match:
                        match['dl_type'] = 0x0800
                    if 'nw_proto' not in match:
                        match['nw_proto'] = 6

                # 查找交换机
                switch = None
                for s in self.net.switches:
                    if s.name == switch_name:
                        switch = s
                        break
                
                if not switch:
                    logger.error(f"未找到交换机: {switch_name}")
                    continue
                
                # 构建OpenFlow命令
                try:
                    # 使用ovs-ofctl添加流表规则，指定 OpenFlow 1.3 协议
                    cmd_parts = ['ovs-ofctl', '-O', 'OpenFlow13', 'add-flow', switch_name]
                    
                    # 构建匹配条件
                    match_str = []
                    if 'dl_type' in match:
                        match_str.append(f"dl_type={match['dl_type']}")
                    if 'dl_src' in match:
                        match_str.append(f"dl_src={match['dl_src']}")
                    if 'dl_dst' in match:
                        match_str.append(f"dl_dst={match['dl_dst']}")
                    if 'nw_src' in match:
                        match_str.append(f"nw_src={match['nw_src']}")
                    if 'nw_dst' in match:
                        match_str.append(f"nw_dst={match['nw_dst']}")
                    if 'nw_proto' in match:
                        match_str.append(f"nw_proto={match['nw_proto']}")
                    if 'tp_src' in match:
                        match_str.append(f"tp_src={match['tp_src']}")
                    if 'tp_dst' in match:
                        match_str.append(f"tp_dst={match['tp_dst']}")
                    
                    # 调试日志：完整match内容
                    logger.info(f"[调试] 下发到 {switch_name} 的流表match: {match}")
                    # 新增：写入ryu.log，便于调试
                    try:
                        with open('ryu.log', 'a', encoding='utf-8') as f:
                            f.write(f"[流表下发] switch={switch_name}, match={json.dumps(match, ensure_ascii=False)}\n")
                    except Exception as e:
                        logger.error(f"写入ryu.log失败: {str(e)}")
                    
                    # 构建动作
                    action_str = []
                    for action in actions:
                        if action['type'] == 'OUTPUT':
                            action_str.append(f"output:{action['port']}")
                    
                    # 组合流表规则
                    flow_rule = ','.join(match_str) + ',actions=' + ','.join(action_str)
                    cmd_parts.append(flow_rule)
                    
                    # 调试日志：最终命令
                    logger.info(f"[调试] 下发到 {switch_name} 的ovs-ofctl命令: {' '.join(cmd_parts)}")
                    
                    # 执行命令
                    result = subprocess.run(cmd_parts, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.info(f"流表规则已添加到 {switch_name}: {flow_rule}")
                        success_count += 1
                    else:
                        logger.error(f"添加流表规则失败: {result.stderr}")
                        
                except Exception as e:
                    logger.error(f"配置流表规则时发生错误: {str(e)}")
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"配置流表时发生错误: {str(e)}")
            return False
    
    def test_connectivity(self):
        """测试网络连通性"""
        try:
            if not self.net:
                logger.error("拓扑未启动")
                return {}
            
            results = {}
            hosts = self.net.hosts
            
            logger.info("开始连通性测试...")
            
            # 检查交换机连接状态
            for switch in self.net.switches:
                connection_status = self.check_switch_connection(switch.name)
                logger.info(f"交换机 {switch.name} 连接状态: {'已连接' if connection_status else '未连接'}")
                
                # 检查流表规则
                flow_rules = switch.cmd(f'ovs-ofctl -O OpenFlow13 dump-flows {switch.name}')
                logger.info(f"交换机 {switch.name} 流表规则:\n{flow_rules}")
            
            # 首先确保所有主机的 ARP 表已经填充
            logger.info("预热主机 ARP 表...")
            for host in hosts:
                # 检查主机网络接口状态
                ifconfig = host.cmd('ifconfig')
                logger.info(f"主机 {host.name} 网络接口状态:\n{ifconfig}")
                
                # 检查主机路由表
                route = host.cmd('route -n')
                logger.info(f"主机 {host.name} 路由表:\n{route}")
                
                for other_host in hosts:
                    if host != other_host:
                        # 先清除 ARP 缓存
                        host.cmd(f'arp -d {other_host.IP()}')
                        # 发送 ARP 请求
                        host.cmd(f'ping -c 1 -W 1 {other_host.IP()} > /dev/null')
                        # 检查 ARP 表
                        arp_table = host.cmd('arp -n')
                        logger.info(f"主机 {host.name} ARP 表:\n{arp_table}")
            
            # 等待控制器处理所有 ARP 请求
            time.sleep(3)
            
            # 进行ping测试
            for i, src_host in enumerate(hosts):
                for j, dst_host in enumerate(hosts):
                    if i != j:  # 不ping自己
                        logger.info(f"测试 {src_host.name} -> {dst_host.name} 的连通性")
                        
                        # 执行ping命令，获取RTT
                        ping_output = src_host.cmd(f'ping -c 3 -W 1 {dst_host.IP()}')
                        logger.info(f"Ping 输出:\n{ping_output}")
                        
                        # 解析ping结果，获取平均RTT
                        try:
                            # 查找包含rtt的行
                            rtt_line = [line for line in ping_output.split('\n') if 'rtt min/avg/max/mdev' in line]
                            if rtt_line:
                                # 提取平均RTT值
                                rtt_parts = rtt_line[0].split('=')
                                if len(rtt_parts) > 1:
                                    rtt_values = rtt_parts[1].strip().split('/')
                                    avg_rtt = float(rtt_values[1])  # 平均RTT在索引1的位置
                                    
                                    # 保存结果
                                    key = f"{src_host.name}->{dst_host.name}"
                                    results[key] = avg_rtt
                                    logger.info(f"{key}: RTT = {avg_rtt} ms")
                                else:
                                    logger.warning(f"无法解析RTT: {rtt_line[0]}")
                            else:
                                logger.warning(f"Ping失败: {ping_output}")
                                results[f"{src_host.name}->{dst_host.name}"] = -1  # 表示失败
                        except Exception as e:
                            logger.error(f"解析ping结果时发生错误: {str(e)}")
                            results[f"{src_host.name}->{dst_host.name}"] = -1  # 表示失败
            
            logger.info("连通性测试完成")
            return results
            
        except Exception as e:
            logger.error(f"连通性测试时发生错误: {str(e)}")
            return {}

    def clear_all_flows(self):
        """清空所有交换机的流表，并输出调试信息"""
        try:
            if not self.net:
                logger.error("拓扑未启动，无法清空流表")
                return False

            url = "http://127.0.0.1:8081/stats/flowentry/delete"

            for switch in self.net.switches:
                try:
                    dpid_int = int(str(switch.dpid), 16)
                    data = {
                        "dpid": dpid_int,
                        "match": {},  # 空匹配字段，表示匹配所有流项
                        "table_id": 0,
                        "out_port": "ANY",  # 注意是字符串，不是整数
                        "out_group": "ANY"
                    }

                    logger.debug(f"发送清空流表请求给 {switch.name} (DPID={dpid_int})：{data}")
                    resp = requests.post(url, json=data, timeout=3)
                    logger.debug(f"收到响应 {resp.status_code}：{resp.text}")

                    if resp.status_code == 200:
                        logger.info(f"已清空交换机 {switch.name} (DPID={dpid_int}) 的流表")
                    else:
                        logger.warning(f"清空交换机 {switch.name} (DPID={dpid_int}) 流表失败: {resp.text}")

                except Exception as e:
                    logger.exception(f"请求清空交换机 {switch.name} 流表时异常: {e}")

            return True

        except Exception as e:
            logger.exception(f"清空所有流表时发生错误: {e}")
            return False


# 将自定义拓扑暴露给 Mininet CLI
topos = {'customtopology': (lambda: CustomTopology())}