#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN匹配域嗅探攻击平台 - 主应用程序
作者: 薛康2200170151 | 王才凤2200170236

运行环境说明：
- 使用系统 Python（非虚拟环境）运行 Flask 后端，以便导入 Mininet
- 通过 subprocess 调用虚拟环境中的 Ryu 控制器
- 需要 sudo 权限运行（因为 Mininet 需要）

启动命令：
  deactivate  # 确保不在虚拟环境
  cd ~/PycharmProjects/SDN_CD
  sudo -E python3 app.py
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import logging
import os
import sys
import subprocess
import signal
import atexit
import json
import threading
import time
from datetime import datetime

# 导入自定义模块
from topology import TopologyManager
from attacker import AttackSimulator
from report import ReportGenerator

app = Flask(__name__)
CORS(app)  # 允许跨域访问

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('attacker.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 全局对象
topology_manager = None
attack_simulator = None
report_generator = None
experiment_state = {
    'topology_running': False,
    'attack_running': False,
    'results': {},
    'logs': [],
    'attack_config': None
}

ALL_FIELDS = ['eth_src', 'eth_dst', 'ip_src', 'ip_dst', 'tcp_src', 'tcp_dst', 'ip_proto']

def init_managers():
    """初始化各个管理器"""
    global topology_manager, attack_simulator, report_generator
    
    topology_manager = TopologyManager()
    attack_simulator = AttackSimulator(topology_manager=topology_manager)
    report_generator = ReportGenerator()
    
    logger.info("管理器初始化完成")
    try:
        with open('attacker.log', 'a', encoding='utf-8') as f:
            f.write('[DEBUG] AttackSimulator 实例化了\n')
    except Exception as e:
        pass

@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'topology_running': experiment_state['topology_running'],
        'attack_running': experiment_state['attack_running']
    })

@app.route('/api/start_topology', methods=['POST'])
def start_topology():
    """启动SDN拓扑"""
    try:
        if experiment_state['topology_running']:
            return jsonify({
                'success': False,
                'message': '拓扑已在运行中'
            }), 400
        
        logger.info("开始启动SDN拓扑...")
        
        # 启动Ryu控制器
        ryu_success = topology_manager.start_ryu_controller()
        if not ryu_success:
            return jsonify({
                'success': False,
                'message': 'Ryu控制器启动失败'
            }), 500
        
        # 启动Mininet拓扑
        topo_success = topology_manager.start_topology()
        if not topo_success:
            return jsonify({
                'success': False,
                'message': 'Mininet拓扑启动失败'
            }), 500
        
        experiment_state['topology_running'] = True
        logger.info("SDN拓扑启动成功")
        
        return jsonify({
            'success': True,
            'message': '拓扑启动成功',
            'topology_info': topology_manager.get_topology_info()
        })
        
    except Exception as e:
        logger.error(f"启动拓扑时发生错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'启动失败: {str(e)}'
        }), 500

@app.route('/api/config_flows', methods=['POST'])
def config_flows():
    """配置流表规则"""
    try:
        if not experiment_state['topology_running']:
            return jsonify({
                'success': False,
                'message': '请先启动拓扑'
            }), 400
        
        logger.info("开始配置流表规则...")
        # 获取前端勾选的匹配域
        req = request.get_json() or {}
        fields = req.get('fields', [])
        logger.info(f"前端选择的流表匹配域: {fields}")
        # 动态生成流表规则
        # 这里只做简单示例，实际可根据需要扩展
        field_map = {
            'eth_src': ('dl_src', '00:00:00:00:00:01'),
            'eth_dst': ('dl_dst', '00:00:00:00:00:02'),
            'ip_src': ('nw_src', '10.0.0.1'),
            'ip_dst': ('nw_dst', '10.0.0.2'),
            'tcp_src': ('tp_src', 1234),
            'tcp_dst': ('tp_dst', 80),
            'ip_proto': ('nw_proto', 6),
        }
        flow_configs = []
        for switch in ['s1', 's2']:
            match = {}
            for field in fields:
                k, v = field_map.get(field, (None, None))
                if k:
                    match[k] = v
            # 补全必要的前置条件
            if 'tp_src' in match or 'tp_dst' in match:
                if 'dl_type' not in match:
                    match['dl_type'] = 0x0800
                if 'nw_proto' not in match:
                    match['nw_proto'] = 6
            elif 'nw_src' in match or 'nw_dst' in match or 'nw_proto' in match:
                if 'dl_type' not in match:
                    match['dl_type'] = 0x0800
            actions = [{'type': 'OUTPUT', 'port': 2 if switch == 's1' else 1}]
            flow_configs.append({
                'switch': switch,
                'match': match,
                'actions': actions
            })
        success = topology_manager.configure_flows(flow_configs)
        if success:
            logger.info("流表配置成功")
            return jsonify({
                'success': True,
                'message': '流表配置成功',
                'flows': flow_configs
            })
        else:
            return jsonify({
                'success': False,
                'message': '流表配置失败'
            }), 500
    except Exception as e:
        logger.error(f"配置流表时发生错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'配置失败: {str(e)}'
        }), 500

@app.route('/api/test_connectivity', methods=['GET'])
def test_connectivity():
    """测试网络连通性"""
    try:
        if not experiment_state['topology_running']:
            return jsonify({
                'success': False,
                'message': '请先启动拓扑'
            }), 400
        
        logger.info("开始连通性测试...")
        
        # 执行ping测试
        connectivity_results = topology_manager.test_connectivity()
        
        logger.info("连通性测试完成")
        return jsonify({
            'success': True,
            'message': '连通性测试完成',
            'results': connectivity_results
        })
        
    except Exception as e:
        logger.error(f"连通性测试时发生错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'测试失败: {str(e)}'
        }), 500

@app.route('/api/start_attack', methods=['POST'])
def start_attack():
    """开始匹配域嗅探攻击"""
    try:
        if not experiment_state['topology_running']:
            return jsonify({
                'success': False,
                'message': '请先启动拓扑'
            }), 400
        
        if experiment_state['attack_running']:
            return jsonify({
                'success': False,
                'message': '攻击已在进行中'
            }), 400
        
        # 获取攻击参数，兼容下划线和驼峰
        attack_config = request.get_json() or {}
        src_ip = attack_config.get('srcIP') or attack_config.get('src_ip', '10.0.0.1')
        dst_ip = attack_config.get('dstIP') or attack_config.get('dst_ip', '10.0.0.2')
        packet_count = attack_config.get('packetCount') or attack_config.get('packet_count', 10)
        interval = attack_config.get('interval', 100)
        fields = ALL_FIELDS  # 强制全字段嗅探
        
        logger.info(f"收到攻击参数: {attack_config}")
        logger.info(f"开始攻击: {src_ip} -> {dst_ip}, 包数量: {packet_count}, interval: {interval}, fields: {fields}")
        
        experiment_state['attack_running'] = True
        experiment_state['attack_config'] = {
            'srcIP': src_ip,
            'dstIP': dst_ip,
            'packetCount': packet_count,
            'interval': interval,
            'fields': fields
        }
        
        # 在新线程中执行攻击
        def run_attack():
            try:
                results = attack_simulator.simulate_attack(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    packet_count=packet_count,
                    interval=interval/1000.0 if interval > 10 else interval,  # 兼容毫秒和秒
                    fields=fields,
                    net=topology_manager.net
                )
                
                experiment_state['results'] = results
                experiment_state['attack_running'] = False
                logger.info("攻击模拟完成")
                
            except Exception as e:
                logger.error(f"攻击执行错误: {str(e)}")
                experiment_state['attack_running'] = False
                try:
                    with open('attacker.log', 'a', encoding='utf-8') as f:
                        f.write(f'[run_attack异常] {str(e)}\n')
                except Exception as log_e:
                    logger.error(f"写attacker.log失败: {str(log_e)}")
        
        attack_thread = threading.Thread(target=run_attack)
        attack_thread.daemon = True
        attack_thread.start()
        
        return jsonify({
            'success': True,
            'message': '攻击已开始',
            'config': {
                'srcIP': src_ip,
                'dstIP': dst_ip,
                'packetCount': packet_count,
                'interval': interval,
                'fields': fields
            }
        })
        
    except Exception as e:
        logger.error(f"启动攻击时发生错误: {str(e)}")
        experiment_state['attack_running'] = False
        return jsonify({
            'success': False,
            'message': f'攻击启动失败: {str(e)}'
        }), 500

@app.route('/api/attack_status', methods=['GET'])
def get_attack_status():
    """获取攻击状态"""
    return jsonify({
        'attack_running': experiment_state['attack_running'],
        'results': experiment_state['results'],
        'has_results': len(experiment_state['results']) > 0,
        'completed': (not experiment_state['attack_running']) and (len(experiment_state['results']) > 0)
    })

@app.route('/api/stop_attack', methods=['POST'])
def stop_attack():
    """停止攻击"""
    try:
        experiment_state['attack_running'] = False
        attack_simulator.stop_attack()
        
        logger.info("攻击已停止")
        return jsonify({
            'success': True,
            'message': '攻击已停止'
        })
        
    except Exception as e:
        logger.error(f"停止攻击时发生错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'停止失败: {str(e)}'
        }), 500

@app.route('/api/export_results', methods=['POST'])
def export_results():
    """导出实验结果"""
    try:
        if not experiment_state['results']:
            return jsonify({
                'success': False,
                'message': '暂无实验结果可导出'
            }), 400
        
        # 生成结果文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sdn_attack_results_{timestamp}.json"
        filepath = os.path.join('exports', filename)
        
        # 确保导出目录存在
        os.makedirs('exports', exist_ok=True)
        
        # 调用_report_generator._analyze_results，返回四个值
        risk_level, risk_description, detected_fields, recommendations = report_generator._analyze_results(experiment_state['results'])
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'experiment_type': 'SDN匹配域嗅探攻击',
            'topology_info': topology_manager.get_topology_info() if topology_manager else {},
            'results': experiment_state['results'],
            'analysis': {
                'risk_level': risk_level,
                'risk_description': risk_description,
                'detected_fields': detected_fields,
                'recommendations': recommendations
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"结果已导出到: {filepath}")
        
        return jsonify({
            'success': True,
            'message': '结果导出成功',
            'filename': filename,
            'download_url': f'/api/download/{filename}'
        })
        
    except Exception as e:
        logger.error(f"导出结果时发生错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'导出失败: {str(e)}'
        }), 500

@app.route('/api/download/<filename>', methods=['GET'])
def download_file(filename):
    """下载文件"""
    try:
        # 安全检查：确保文件名不包含路径操作符
        if '..' in filename or filename.startswith('/'):
            return jsonify({
                'success': False,
                'message': '非法的文件名'
            }), 400
            
        # 构建文件路径
        filepath = os.path.join('exports', filename)
        
        # 检查文件是否存在
        if not os.path.exists(filepath):
            return jsonify({
                'success': False,
                'message': '文件不存在'
            }), 404
            
        # 获取文件MIME类型
        mime_type = 'text/html' if filename.endswith('.html') else 'application/json'
        
        # 返回文件
        return send_file(
            filepath,
            mimetype=mime_type,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"下载文件时发生错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'下载失败: {str(e)}'
        }), 500

@app.route('/api/generate_report', methods=['POST'])
def generate_report():
    """生成完整报告"""
    try:
        if not experiment_state['results']:
            return jsonify({
                'success': False,
                'message': '暂无实验数据可生成报告'
            }), 400
            
        # 获取请求数据
        config = request.get_json(silent=True) or {}
        report_format = config.get('format', 'html').lower()
        
        # 验证格式
        if report_format not in ['html', 'json']:
            return jsonify({
                'success': False,
                'message': f'不支持的报告格式: {report_format}'
            }), 400
            
        # 确保attack_config有值
        attack_config = experiment_state.get('attack_config') or {}
        
        # 生成报告
        report_data = report_generator.generate_full_report(
            topology_info=topology_manager.get_topology_info() if topology_manager else {},
            attack_config=attack_config,
            results=experiment_state['results'],
            format=report_format
        )
        
        # 保存报告文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sdn_security_report_{timestamp}.{report_format}"
        filepath = os.path.join('exports', filename)
        
        # 确保导出目录存在
        os.makedirs('exports', exist_ok=True)
        
        # 写入文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_data)
            
        logger.info(f"报告已生成: {filepath}")
        
        return jsonify({
            'success': True,
            'message': '报告生成成功',
            'filename': filename,
            'download_url': f'/api/download/{filename}'
        })
        
    except Exception as e:
        logger.error(f"生成报告时发生错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'报告生成失败: {str(e)}'
        }), 500

@app.route('/api/stop_topology', methods=['POST'])
def stop_topology():
    """停止拓扑"""
    try:
        if not experiment_state['topology_running']:
            return jsonify({
                'success': False,
                'message': '拓扑未在运行'
            }), 400
        
        # 停止攻击（如果正在运行）
        if experiment_state['attack_running']:
            experiment_state['attack_running'] = False
            attack_simulator.stop_attack()
        
        # 停止拓扑
        topology_manager.stop_topology()
        experiment_state['topology_running'] = False
        
        logger.info("拓扑已停止")
        
        return jsonify({
            'success': True,
            'message': '拓扑已停止'
        })
        
    except Exception as e:
        logger.error(f"停止拓扑时发生错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'停止失败: {str(e)}'
        }), 500

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """获取系统日志"""
    try:
        # 读取日志文件最后100行
        log_lines = []
        if os.path.exists('attacker.log'):
            with open('attacker.log', 'r', encoding='utf-8') as f:
                lines = f.readlines()
                log_lines = lines[-100:]  # 最后100行
        
        return jsonify({
            'success': True,
            'logs': [line.strip() for line in log_lines]
        })
        
    except Exception as e:
        logger.error(f"获取日志时发生错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'获取日志失败: {str(e)}'
        }), 500

def signal_handler(sig, frame):
    """处理信号，确保程序正常退出"""
    logger.info("接收到终止信号，正在清理资源...")
    if topology_manager:
        if experiment_state['topology_running']:
            topology_manager.stop_topology()
            experiment_state['topology_running'] = False
        if topology_manager.ryu_process and topology_manager.ryu_process.poll() is None:
            topology_manager.stop_ryu_controller()
    sys.exit(0)

def cleanup():
    """程序退出时的清理工作"""
    logger.info("程序退出，执行清理工作...")
    if topology_manager:
        if experiment_state['topology_running']:
            topology_manager.stop_topology()
        if topology_manager.ryu_process and topology_manager.ryu_process.poll() is None:
            topology_manager.stop_ryu_controller()

if __name__ == '__main__':
    # 检查是否以root权限运行
    if os.geteuid() != 0:
        print("错误: 此程序需要以root权限运行（sudo python3 app.py）")
        sys.exit(1)
    
    # 检查Python路径，确认是否使用了系统 Python
    python_path = sys.executable
    if 'env_py397' in python_path:
        print(f"警告: 当前Python路径 {python_path} 是虚拟环境中的Python")
        print("请先退出虚拟环境（deactivate）后再运行")
        sys.exit(1)
    
    # 确保导出目录存在
    os.makedirs('exports', exist_ok=True)
    
    # 配置日志系统
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('attacker.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger(__name__)
    
    # 初始化管理器
    init_managers()
    
    # 注册信号处理和退出清理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(cleanup)
    
    # 启动Flask应用
    logger.info("SDN匹配域嗅探攻击平台后端服务启动")
    logger.info("当前环境: " + os.environ.get('VIRTUAL_ENV', '非虚拟环境'))
    logger.info("服务地址: http://localhost:5000")
    
    try:
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False,  # 在生产环境中禁用debug模式
            threaded=True,
            use_reloader=False  # 禁用重载器，避免启动多个进程
        )
    except Exception as e:
        logger.error(f"启动Flask服务时发生错误: {str(e)}")
        sys.exit(1)