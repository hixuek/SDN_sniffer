#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SDN匹配域嗅探攻击平台 - Ryu控制器应用
作者: 薛康2200170151 | 王才凤2200170236
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib
from webob import Response
import json

# 控制器应用名称
controller_instance_name = 'controller_api_app'

class MatchFieldSniffer(app_manager.RyuApp):
    """
    匹配域嗅探攻击检测控制器
    支持OpenFlow 1.3协议
    提供REST API接口用于流表配置
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    
    def __init__(self, *args, **kwargs):
        super(MatchFieldSniffer, self).__init__(*args, **kwargs)
        self.switches = {}  # 存储交换机信息
        self.mac_to_port = {}  # MAC地址到端口的映射
        
        # 注册REST API
        wsgi = kwargs['wsgi']
        wsgi.register(ControllerRestApi, 
                     {controller_instance_name: self})
        
        self.logger.info("匹配域嗅探控制器已启动")
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        处理交换机连接事件，安装默认流表
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # 获取交换机ID
        dpid = datapath.id
        self.switches[dpid] = datapath
        self.mac_to_port.setdefault(dpid, {})
        
        self.logger.info(f"交换机 {dpid} 已连接")
        
        # 安装默认流表：将未匹配的数据包发送到控制器
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """
        添加流表规则
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        处理PacketIn事件
        """
        # 提取事件信息
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        # 解析数据包
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # 忽略LLDP数据包
        if eth.ethertype == 0x88cc:
            return
        
        dst_mac = eth.dst
        src_mac = eth.src
        
        # 记录MAC地址到端口的映射
        self.mac_to_port[dpid][src_mac] = in_port
        
        # 检查是否已知目标MAC地址的端口
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            # 未知目标MAC，泛洪
            out_port = ofproto.OFPP_FLOOD
        
        # 构造输出动作
        actions = [parser.OFPActionOutput(out_port)]
        
        # 如果不是泛洪，则添加流表规则
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            
            # 检查是否有缓存的数据包
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        
        # 构造数据包输出消息
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


class ControllerRestApi(ControllerBase):
    """
    REST API接口
    提供流表配置和拓扑信息查询功能
    """
    def __init__(self, req, link, data, **config):
        super(ControllerRestApi, self).__init__(req, link, data, **config)
        self.controller_app = data[controller_instance_name]
    
    @route('controller', '/stats/switches', methods=['GET'])
    def get_switches(self, req, **kwargs):
        """获取所有交换机"""
        switches = list(self.controller_app.switches.keys())
        body = json.dumps(switches)
        return Response(content_type='application/json', body=body)
    
    @route('controller', '/stats/flow/{dpid}', methods=['GET'])
    def get_flows(self, req, **kwargs):
        """获取指定交换机的流表"""
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        if dpid not in self.controller_app.switches:
            return Response(status=404, body=json.dumps({"error": "Switch not found"}))
        
        # 这里应该实现获取流表的逻辑，但需要额外的代码
        # 简化版本，返回空列表
        flows = []
        body = json.dumps(flows)
        return Response(content_type='application/json', body=body)
    
    @route('controller', '/stats/flowentry/add', methods=['POST'])
    def add_flow_entry(self, req, **kwargs):
        """添加流表规则"""
        try:
            flow_config = json.loads(req.body)
            dpid = dpid_lib.str_to_dpid(flow_config.get('dpid', ''))
            
            if dpid not in self.controller_app.switches:
                return Response(status=404, body=json.dumps({"error": "Switch not found"}))
            
            datapath = self.controller_app.switches[dpid]
            parser = datapath.ofproto_parser
            
            # 解析匹配条件
            match_fields = flow_config.get('match', {})
            match = parser.OFPMatch(**match_fields)
            
            # 解析动作
            actions = []
            for action in flow_config.get('actions', []):
                action_type = action.get('type', '')
                if action_type == 'OUTPUT':
                    port = action.get('port')
                    actions.append(parser.OFPActionOutput(port))
            
            # 添加流表
            priority = flow_config.get('priority', 1)
            self.controller_app.add_flow(datapath, priority, match, actions)
            
            return Response(content_type='application/json', 
                           body=json.dumps({"status": "success"}))
            
        except Exception as e:
            return Response(status=400, 
                           body=json.dumps({"error": str(e)}))
    
    @route('controller', '/stats/flowentry/delete', methods=['POST'])
    def delete_flow_entry(self, req, **kwargs):
        """删除流表规则"""
        try:
            flow_config = json.loads(req.body)
            dpid = dpid_lib.str_to_dpid(flow_config.get('dpid', ''))
            
            if dpid not in self.controller_app.switches:
                return Response(status=404, body=json.dumps({"error": "Switch not found"}))
            
            datapath = self.controller_app.switches[dpid]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            # 构造删除消息
            match = parser.OFPMatch(**flow_config.get('match', {}))
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            
            datapath.send_msg(mod)
            
            return Response(content_type='application/json', 
                           body=json.dumps({"status": "success"}))
            
        except Exception as e:
            return Response(status=400, 
                           body=json.dumps({"error": str(e)}))
