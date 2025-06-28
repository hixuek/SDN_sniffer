# SDN_sniffer
SDN 匹配域嗅探攻击
# SDN匹配域嗅探攻击研究平台

本项目是一个用于研究和检测SDN网络中匹配域嗅探攻击的实验平台。通过模拟攻击场景，分析SDN交换机流表中的匹配域配置对网络性能的影响，帮助研究人员理解和防范此类安全威胁。

## 功能特点

- 🚀 完整的SDN网络拓扑模拟
- 🔍 匹配域嗅探攻击模拟与检测
- 📊 实时RTT(往返时间)测量与分析
- 🌐 基于Flask的RESTful API接口
- 📈 实验结果可视化与报告生成
- 🔄 支持OpenFlow 1.3协议

## 系统架构

```
+-------------------+       +-------------------+       +-------------------+
|                   |       |                   |       |                   |
|   Web前端界面     |<----->|   Flask后端服务   |<----->|   Ryu控制器      |
|   (HTML/JS)      |       |   (Python)        |       |   (OpenFlow 1.3)  |
+-------------------+       +-------------------+       +-------------------+
                                                             |
                                                             |
                                                     +------v------+
                                                     |             |
                                                     |  Mininet    |
                                                     |  网络模拟器  |
                                                     |             |
                                                     +-------------+
```


## 环境要求

### 系统要求
- Ubuntu 18.04/20.04 LTS
- Python 3.6+

### 主要组件
- Mininet 2.3.0+ (使用系统Python环境)
- Ryu 4.34+ (使用虚拟环境)
- Scapy 2.4.0+
- Flask 2.0.0+
- NumPy
- Matplotlib

## 安装指南

### 1. 克隆仓库
```bash
git clone [您的仓库URL]
cd SDN_CD
```

### 2. 设置Python虚拟环境（用于Ryu）
```bash
# 创建虚拟环境
python3 -m venv ~/venv/ryu-env

# 激活虚拟环境
source ~/venv/ryu-env/bin/activate

# 安装Ryu
pip install ryu

# 安装其他依赖
pip install -r requirements.txt

# 退出虚拟环境
deactivate
```

### 3. 安装Mininet（使用系统Python）
```bash
# 确保在系统Python环境下（不在虚拟环境中）
deactivate 2>/dev/null || true

# 安装Mininet
git clone git://github.com/mininet/mininet
cd mininet
sudo ./util/install.sh -n

# 安装系统级依赖
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev

# 安装Python依赖（系统Python）
sudo pip3 install -r requirements.txt
```

### 4. 环境变量配置
将以下内容添加到 `~/.bashrc` 或 `~/.bash_profile` 中：

```bash
# 设置Ryu虚拟环境激活别名
alias start-ryu='source ~/venv/ryu-env/bin/activate'

export PATH=$PATH:~/mininet/util  # 添加Mininet工具到PATH
```

然后运行：
```bash
source ~/.bashrc  # 或 source ~/.bash_profile
```

## 快速开始

### 1. 启动Ryu控制器
打开一个新终端，激活Ryu虚拟环境并启动控制器：

```bash
# 激活Ryu虚拟环境
start-ryu

# 启动Ryu控制器
ryu-manager ryu_app.py
```

### 2. 启动主应用程序
打开另一个终端，使用系统Python启动主应用：

```bash
# 确保不在虚拟环境中
deactivate 2>/dev/null || true

# 启动主应用（需要root权限）
sudo -E python3 app.py
```

### 3. 访问Web界面
打开浏览器访问：`http://localhost:5000`

2. 打开浏览器访问：`http://localhost:5000`

3. 通过Web界面进行以下操作：
   - 启动/停止SDN拓扑
   - 配置流表规则
   - 执行匹配域嗅探攻击
   - 查看实时结果和日志
   - 导出实验报告

## 项目结构

```
SDN_CD/
├── app.py                 # 主应用程序入口
├── ryu_app.py            # Ryu控制器应用
├── attacker.py           # 攻击模拟器实现
├── topology.py           # 网络拓扑定义
├── report.py             # 报告生成模块
├── sdn_attack_gui.html   # 网页前端界面
├── requirements.txt      # Python依赖
└── README.md            # 项目说明文档
```

## API文档

### 1. 拓扑管理

- `POST /api/topology/start` - 启动SDN拓扑
- `POST /api/topology/stop` - 停止SDN拓扑
- `GET /api/topology/status` - 获取拓扑状态

### 2. 流表管理

- `POST /api/flows/config` - 配置流表规则
- `GET /api/flows` - 获取当前流表

### 3. 攻击测试

- `POST /api/attack/start` - 开始攻击测试
- `GET /api/attack/status` - 获取攻击状态
- `POST /api/attack/stop` - 停止攻击测试

### 4. 结果管理

- `GET /api/results` - 获取测试结果
- `GET /api/results/export` - 导出测试结果
- `GET /api/report` - 生成实验报告

## 使用示例

1. 启动拓扑
   ```bash
   curl -X POST http://localhost:5000/api/topology/start
   ```

2. 配置流表规则
   ```bash
   curl -X POST http://localhost:5000/api/flows/config \
        -H "Content-Type: application/json" \
        -d '{"src_ip":"10.0.0.1", "dst_ip":"10.0.0.2", "priority":1}'
   ```

3. 开始攻击测试
   ```bash
   curl -X POST http://localhost:5000/api/attack/start \
        -H "Content-Type: application/json" \
        -d '{"src_ip":"10.0.0.1", "dst_ip":"10.0.0.2", "packet_count":10}'
   ```

## 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 许可证


## 作者

- hixuek


## 致谢

- 感谢Mininet和Ryu项目提供的优秀SDN开发框架
- 感谢所有贡献者和用户的支持与反馈
