#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN匹配域嗅探攻击模拟器
负责执行匹配域嗅探攻击并收集RTT数据
"""

import logging
import time
import threading
import statistics
import random
from scapy.all import IP, TCP, UDP, Ether, srp1, sr1, conf
import numpy as np

# 只要被import就写日志
try:
    with open('attacker.log', 'a', encoding='utf-8') as f:
        f.write('[DEBUG] attacker.py 被 import 了\n')
except Exception as e:
    pass

# 配置日志记录
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(
    level=logging.DEBUG,  # 设置为DEBUG级别以显示更多信息
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('attacker.log', mode='a', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# 支持的匹配域字段
ALL_FIELDS = [
    'eth_src',    # 源MAC地址
    'eth_dst',    # 目标MAC地址
    'ip_src',     # 源IP地址
    'ip_dst',     # 目标IP地址
    'tcp_src',    # TCP源端口
    'tcp_dst',    # TCP目标端口
    'ip_proto'    # IP协议号
]

class AttackSimulator:
    """攻击模拟器"""
    
    def __init__(self, topology_manager=None):
        try:
            with open('/tmp/attacker_debug.txt', 'a') as f:
                f.write('AttackSimulator __init__ called\n')
        except Exception as e:
            pass
        self.running = False
        self.results = {}
        self.attack_thread = None
        self.topology_manager = topology_manager
        self._probe_log_flags = {}  # 新增：记录每个字段是否已输出过典型日志
        logger.info("攻击模拟器初始化完成")
    
    def simulate_attack(self, src_ip, dst_ip, packet_count=5, interval=0.05, fields=None, net=None):
        """执行匹配域嗅探攻击
        
        参数:
            src_ip: 源IP地址
            dst_ip: 目标IP地址
            packet_count: 每个字段发送的数据包数量
            interval: 数据包发送间隔(秒)
            fields: 要测试的匹配域列表
            net: Mininet网络对象
            
        返回:
            包含各匹配域RTT测量结果的字典
        """
        try:
            logger.info(f"[入口] simulate_attack被调用: src_ip={src_ip}, dst_ip={dst_ip}, packet_count={packet_count}, interval={interval}, fields={fields}, net={'有' if net else '无'}")
            
            self.net = net
            self.results = {}
            self.running = True
            
            if fields is None:
                fields = ALL_FIELDS
                logger.info(f"使用默认匹配域: {fields}")
            
            for field in fields:
                if not self.running:
                    break
                    
                logger.info(f"开始测试字段: {field}")
                is_used, base_rtt, probe_rtt = self.probe_match_field(
                    src_ip, dst_ip, field, packet_count
                )
                
                self.results[field] = {
                    'is_used': is_used,
                    'base_rtt': base_rtt,
                    'probe_rtt': probe_rtt,
                    'rtt_diff': probe_rtt - base_rtt if base_rtt > 0 and probe_rtt > 0 else 0
                }
                
                # 添加间隔
                if interval > 0:
                    time.sleep(interval)
                
            logger.info("匹配域嗅探攻击完成")
            return self.results
            
        except Exception as e:
            logger.error(f"执行攻击时出错: {str(e)}", exc_info=True)
            return {}
    
    def _run_attack(self, src_ip, dst_ip, packet_count, interval, fields, net):
        try:
            with open('/tmp/attacker_debug.txt', 'a') as f:
                f.write(f'_run_attack called: src_ip={src_ip}, dst_ip={dst_ip}\n')
        except Exception as e:
            pass
        logger.info(f"[入口] _run_attack线程启动: src_ip={src_ip}, dst_ip={dst_ip}, packet_count={packet_count}, interval={interval}, fields={fields}, net={'有' if net else '无'}")
        """执行攻击的线程函数"""
        try:
            logger.info(f"开始匹配域嗅探攻击: {src_ip} -> {dst_ip}")
            
            # 查找源主机
            src_host = None
            if net:
                for host in net.hosts:
                    if host.IP() == src_ip:
                        src_host = host
                        logger.info(f"找到源主机: {host.name}")
                        break
            
            self._probe_log_flags = {}  # 每次攻击前重置
            
            # 对每个匹配域进行测试
            for field in fields:
                if not self.running:
                    logger.info("攻击已停止")
                    break
                
                # 每次切换字段前清空所有交换机流表
                # if self.topology_manager:
                #     self.topology_manager.clear_all_flows()
                
                logger.info(f"开始测试匹配域: {field}")
                logger.info(f"[调试] 即将对字段 {field} 发送 {packet_count} 个探测包")
                rtts = []
                start_time = time.time()
                
                # 发送探测包并测量RTT
                for i in range(packet_count):
                    if not self.running:
                        break
                    
                    logger.debug(f"发送第 {i+1}/{packet_count} 个探测包")
                    # 根据当前测试的匹配域构造数据包
                    if src_host:
                        # 使用Mininet主机发送数据包
                        rtt = self._send_probe_from_mininet(src_host, dst_ip, field, i)
                    else:
                        # 直接使用Scapy发送数据包
                        rtt = self._send_probe_with_scapy(src_ip, dst_ip, field, i)
                    
                    if rtt > 0:
                        rtts.append(rtt)
                        logger.debug(f"探测包 {i+1} RTT: {rtt:.2f}ms")
                    else:
                        logger.warning(f"探测包 {i+1} 失败")
                    
                    # 等待指定间隔
                    time.sleep(interval)
                logger.info(f"[调试] 字段 {field} 的探测包发送完毕")
                end_time = time.time()
                logger.info(f"匹配域 {field} 测试完成，耗时: {end_time - start_time:.2f}秒")
                
                # 计算统计数据
                if rtts:
                    avg_rtt = statistics.mean(rtts)
                    min_rtt = min(rtts)
                    max_rtt = max(rtts)
                    variance = statistics.variance(rtts) if len(rtts) > 1 else 0
                    
                    self.results[field] = {
                        'avgRTT': avg_rtt,
                        'minRTT': min_rtt,
                        'maxRTT': max_rtt,
                        'variance': variance,
                        'samples': rtts
                    }
                    
                    logger.info(f"{field} 统计结果: 平均RTT = {avg_rtt:.2f}ms, 方差 = {variance:.2f}")
                else:
                    logger.warning(f"{field}: 未收集到有效RTT数据")
                    self.results[field] = {
                        'avgRTT': 0,
                        'minRTT': 0,
                        'maxRTT': 0,
                        'variance': 0,
                        'samples': []
                    }
            
            logger.info("匹配域嗅探攻击完成")
            
        except Exception as e:
            try:
                with open('/tmp/attacker_debug.txt', 'a') as f:
                    f.write(f'_run_attack exception: {str(e)}\n')
            except Exception as e2:
                pass
            logger.error(f"执行攻击时发生错误: {str(e)}", exc_info=True)
        finally:
            self.running = False
    
    def _send_probe_from_mininet(self, src_host, dst_ip, field, seq, test_value=None):
        """从Mininet主机发送探测包"""
        try:
            # 根据字段类型构造不同的命令
            if field in ['eth_src', 'eth_dst', 'ip_src', 'ip_dst', 'ip_proto']:
                # 使用scapy发送更复杂的包
                return self._send_probe_with_scapy(src_host.IP(), dst_ip, field, seq, test_value)
            
            # 对于TCP/UDP端口，使用hping3
            elif field == 'tcp_src':
                port = test_value if test_value else random.randint(1024, 65535)
                cmd = f"hping3 -S -p 80 -s {port} -c 1 --fast {dst_ip}"
            elif field == 'tcp_dst':
                port = test_value if test_value else random.randint(1, 1023)
                cmd = f"hping3 -S -s 1234 -p {port} -c 1 --fast {dst_ip}"
            else:
                cmd = f"ping -c 1 -W 0.5 {dst_ip}"
            
            # 记录命令
            if not self._probe_log_flags.get(field):
                logger.info(f"[MININET] 字段 {field} 的探测命令: {cmd}")
                self._probe_log_flags[field] = True
            
            # 执行命令并测量RTT
            start_time = time.time()
            output = src_host.cmd(cmd)
            rtt = (time.time() - start_time) * 1000  # 转换为毫秒
            
            # 检查命令是否成功
            if "1 packets transmitted, 1 received" in output:
                logger.debug(f"[MININET] 收到回复: {field}, seq={seq}, RTT={rtt:.2f}ms")
                return rtt
            else:
                logger.warning(f"[MININET] 未收到回复: {field}, seq={seq}, 输出: {output}")
                return -1
                
        except Exception as e:
            logger.error(f"[MININET] 发送探测包时出错: {str(e)}")
            return -1
    
    def _send_probe_with_scapy(self, src_ip, dst_ip, field, seq, test_value=None):
        """使用Scapy发送探测包
        
        参数:
            src_ip: 源IP
            dst_ip: 目标IP
            field: 要测试的字段
            seq: 序列号
            test_value: 测试值，如果为None则使用默认值
        """
        try:
            # 禁用Scapy输出
            conf.verb = 0
            
            # 生成随机MAC地址
            def random_mac():
                return f"02:00:00:{random.randint(0, 0xff):02x}:{random.randint(0, 0xff):02x}:{random.randint(0, 0xff):02x}"
            
            # 基础数据包
            eth = Ether()
            ip = IP(src=src_ip, dst=dst_ip)
            
            # 根据字段类型设置默认值
            if field == 'eth_src':
                eth.src = test_value if test_value else random_mac()
                packet = eth / ip / ICMP()
            elif field == 'eth_dst':
                eth.dst = test_value if test_value else random_mac()
                packet = eth / ip / ICMP()
            elif field == 'ip_src':
                ip.src = test_value if test_value else f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
                packet = eth / ip / ICMP()
            elif field == 'ip_dst':
                ip.dst = test_value if test_value else f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
                packet = eth / ip / ICMP()
            elif field == 'tcp_src':
                packet = eth / ip / TCP(sport=test_value if test_value else random.randint(1024, 65535), dport=80)
            elif field == 'tcp_dst':
                packet = eth / ip / TCP(sport=random.randint(1024, 65535), dport=test_value if test_value else random.randint(1, 1023))
            elif field == 'ip_proto':
                proto = test_value if test_value else random.choice([6, 17, 1])  # TCP, UDP, ICMP
                ip.proto = proto
                if proto == 6:  # TCP
                    packet = eth / ip / TCP()
                elif proto == 17:  # UDP
                    packet = eth / ip / UDP()
                else:  # ICMP
                    packet = eth / ip / ICMP()
            else:
                packet = eth / ip / ICMP()
            
            # 记录发送的包
            if not self._probe_log_flags.get(field):
                logger.info(f"[SCAPY] 字段 {field} 的探测包: {packet.summary()}")
                self._probe_log_flags[field] = True
            
            # 发送包并测量RTT
            start_time = time.time()
            response = srp1(packet, timeout=0.5, verbose=0)
            rtt = (time.time() - start_time) * 1000  # 转换为毫秒
            
            if response:
                logger.debug(f"[SCAPY] 收到回复: {field}, seq={seq}, RTT={rtt:.2f}ms")
                return rtt
            else:
                logger.warning(f"[SCAPY] 超时未收到回复: {field}, seq={seq}")
                return -1
                
        except Exception as e:
            logger.error(f"[SCAPY] 发送探测包时出错: {str(e)}")
            return -1
    def probe_match_field(self, src_ip, dst_ip, field, packet_count=10):
        """探测指定字段是否被用作匹配域
        
        参数:
            src_ip: 源IP
            dst_ip: 目标IP
            field: 要测试的字段
            packet_count: 每个测试发送的包数量
            
        返回:
            (is_used, base_rtt, probe_rtt): 
                is_used: 该字段是否被用作匹配域
                base_rtt: 基准RTT(毫秒)
                probe_rtt: 探测RTT(毫秒)
        """
        try:
            logger.info(f"开始探测字段: {field}")
            
            # 清空之前的日志标志
            self._probe_log_flags = {}
            
            # 查找源主机
            src_host = None
            if self.net:
                for host in self.net.hosts:
                    if host.IP() == src_ip:
                        src_host = host
                        break
            
            # 1. 清空流表
            if self.topology_manager:
                self.topology_manager.clear_all_flows()
                time.sleep(1)  # 等待流表清空
            
            # 2. 添加默认规则
            if self.topology_manager:
                self.topology_manager.configure_flows([
                    {
                        "switch": "s1",
                        "match": {},
                        "actions": [{"type": "OUTPUT", "port": "NORMAL"}],
                        "priority": 0
                    }
                ])
            
            # 3. 发送基准包
            base_rtts = []
            for i in range(packet_count):
                if src_host:
                    rtt = self._send_probe_from_mininet(src_host, dst_ip, field, i, None)
                else:
                    rtt = self._send_probe_with_scapy(src_ip, dst_ip, field, i, None)
                if rtt > 0:
                    base_rtts.append(rtt)
                time.sleep(0.1)  # 避免过载
            
            if not base_rtts:
                logger.error(f"无法获取基准RTT")
                return False, 0, 0
            
            # 4. 添加测试流表规则
            if self.topology_manager:
                match = {field: "test_value"}
                self.topology_manager.configure_flows([
                    {
                        "switch": "s1",
                        "match": match,
                        "actions": [{"type": "OUTPUT", "port": "NORMAL"}],
                        "priority": 10
                    }
                ])
                time.sleep(1)  # 等待规则生效
            
            # 5. 发送探测包
            probe_rtts = []
            for i in range(packet_count):
                if src_host:
                    rtt = self._send_probe_from_mininet(src_host, dst_ip, field, i, "test_value")
                else:
                    rtt = self._send_probe_with_scapy(src_ip, dst_ip, field, i, "test_value")
                if rtt > 0:
                    probe_rtts.append(rtt)
                time.sleep(0.1)  # 避免过载
            
            if not probe_rtts:
                logger.error(f"无法获取探测RTT")
                return False, 0, 0
            
            # 6. 计算平均RTT
            avg_base_rtt = statistics.mean(base_rtts)
            avg_probe_rtt = statistics.mean(probe_rtts)
            
            # 7. 判断差异是否显著
            threshold = 0.5  # 阈值，单位毫秒
            is_used = (avg_probe_rtt - avg_base_rtt) > threshold
            
            logger.info(f"字段 {field} 探测完成: 基准RTT={avg_base_rtt:.2f}ms, 探测RTT={avg_probe_rtt:.2f}ms, 是否匹配域: {'是' if is_used else '否'}")
            
            return is_used, avg_base_rtt, avg_probe_rtt
            
        except Exception as e:
            logger.error(f"探测字段 {field} 时出错: {str(e)}", exc_info=True)
            return False, 0, 0

    def stop_attack(self):
        """停止攻击"""
        logger.info("正在停止攻击...")
        self.running = False
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=2)
            logger.info("攻击已停止")
