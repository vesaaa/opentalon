# OpenTalon (利爪) —— 你的全栖网络与存储管控中枢

<p align="center">
  <img src="webui/web/logo-opentalon-light.png" alt="OpenTalon 利爪 Logo" width="260" />
</p>

> **单体极简部署，网关自动推导拓扑连线** — 开源跨平台设备管理与拓扑监控平台

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://go.dev)
[![Author](https://img.shields.io/badge/Author-vesaa-green.svg)](https://github.com/vesaa)

## ✨ 核心特性

| 特性 | 描述 |
|------|------|
| **单体二进制** | Server + 前端 UI 编译为一个文件，零依赖部署 |
| **网关自动推导** | Agent 上报本机 IP + 默认网关，Server 自动建立父子拓扑连线 |
| **AntV G6 拓扑图** | 可拖拽节点，箭头连线，点击节点弹出实时 Metrics 抽屉 |
| **跨平台 Agent** | 支持 Linux / Windows / macOS，采集 CPU/内存/磁盘/TCP/UDP/带宽 |
| **SSH 兜底** | 对无法部署 Agent 的设备（路由器等）提供 SSH 批量运维能力 |

## 🚀 快速开始

### 安装

#### 一键安装（推荐，Linux / macOS）

```bash
# 安装最新版本的 Server 并注册为系统服务
curl -fsSL https://raw.githubusercontent.com/vesaaa/opentalon/main/scripts/install.sh | sh -s server

# 安装指定版本的 Agent（必须指定 join/token）
curl -fsSL https://raw.githubusercontent.com/vesaaa/opentalon/main/scripts/install.sh | sh -s agent --version v0.1.18 --join 192.168.1.1:1616 --token opentalon-secret-key-123
```

#### 卸载（服务保留二进制）

```bash
# 卸载 Server 服务
curl -fsSL https://raw.githubusercontent.com/vesaaa/opentalon/main/scripts/install.sh | sh -s uninstall server

# 卸载 Agent 服务
curl -fsSL https://raw.githubusercontent.com/vesaaa/opentalon/main/scripts/install.sh | sh -s uninstall agent

# 一键卸载全部服务（server + agent）
curl -fsSL https://raw.githubusercontent.com/vesaaa/opentalon/main/scripts/install.sh | sh -s uninstall
```

#### 手动下载二进制

```bash
# Linux amd64 通用版（推荐，适用于 CentOS 7 / Debian / Ubuntu / Rocky / Alpine 等）
curl -L https://github.com/vesaaa/opentalon/releases/latest/download/opentalon-linux-amd64 -o opentalon
chmod +x opentalon

# Alpine Linux amd64 (兼容旧脚本，功能同上)
curl -L https://github.com/vesaaa/opentalon/releases/latest/download/opentalon-linux-amd64-alpine -o opentalon
chmod +x opentalon

# Linux arm64
curl -L https://github.com/vesaaa/opentalon/releases/latest/download/opentalon-linux-arm64 -o opentalon
chmod +x opentalon

# Linux armv7 (32-bit)
curl -L https://github.com/vesaaa/opentalon/releases/latest/download/opentalon-linux-armv7 -o opentalon
chmod +x opentalon

# macOS amd64 (Intel)
curl -L https://github.com/vesaaa/opentalon/releases/latest/download/opentalon-darwin-amd64 -o opentalon
chmod +x opentalon

# macOS arm64 (Apple Silicon)
curl -L https://github.com/vesaaa/opentalon/releases/latest/download/opentalon-darwin-arm64 -o opentalon
chmod +x opentalon

# Windows amd64 (PowerShell)
Invoke-WebRequest -Uri "https://github.com/vesaaa/opentalon/releases/latest/download/opentalon-windows-amd64.exe" -OutFile opentalon.exe
```

### 启动 Server

```bash
./opentalon server
# 控制平面（Web UI + API）: http://localhost:6677
# 数据平面（Agent 上报） : http://localhost:1616
```

### 纳管设备（Agent）

```bash
# 在需要被管理的设备上运行（join 不带端口时默认使用 data_port，例如 1616）：
./opentalon agent --join 192.168.1.1 --token opentalon-secret-key-123

# 指定分组和 PVE 父节点（可选）：
./opentalon agent --join 192.168.1.1 --token opentalon-secret-key-123 --group "虚拟化" --parent 3

# 排查问题时可打开 HTTP 日志：
./opentalon agent --join 192.168.1.1 --token opentalon-secret-key-123 --debug-http
```

> Agent 启动后自动向 Server 注册，Server 根据该设备上报的 **默认网关 IP** 自动将其连线到对应父节点，无需手动配置拓扑。

## 📁 目录结构

```
opentalon/
├── main.go                    # 统一 CLI 入口 (cobra)
├── internal/
│   ├── config/config.go       # Viper 配置 + 智能默认值
│   ├── models/                # GORM 数据模型
│   │   ├── device.go          # Device (IP, GatewayIP, ParentID, Group)
│   │   └── metrics.go         # Metrics (CPU/Mem/Disk/TCP/UDP/Rx/Tx)
│   ├── agent/
│   │   ├── collector.go       # gopsutil 跨平台采集 + 网关检测
│   │   └── agent.go           # 心跳上报逻辑
│   └── server/
│       ├── db.go              # GORM + SQLite + 自动父子推导
│       ├── api.go             # Gin RESTful API
│       ├── ssh.go             # SSH 兜底运维模块
│       └── embed.go           # go:embed 静态文件
└── web/
    ├── index.html             # Vue 3 + AntV G6 看板
    └── dist/                  # 生产前端构建产物目录
```

## ⚙️ 配置

默认配置（可通过 `config.yaml` 或 `TALON_*` 环境变量覆盖）：

```yaml
server_host:           "0.0.0.0"
control_port:          6677      # Web UI + 控制平面 API
data_port:             1616      # Agent 上报数据平面
db_path:               "opentalon.db"
db_driver:             "sqlite"

jwt_secret:            "OtLn$Xq7@wP2!mZ9#rK6^dV4&eA1*fY"
agent_token:           "opentalon-secret-key-123"
admin_user:            "admin"
admin_pass:            "admin"

main_router_ip:        "192.168.1.1"
side_router_ip:        "192.168.1.2"

agent_join_addr:       "127.0.0.1:1616"
agent_interval_seconds: 30
agent_group:           "default"
agent_network_mode:    "Bridged"
agent_outbound_token:  "opentalon-secret-key-123"
```

> **提示**：生产环境务必修改 `jwt_secret`、`agent_token`、`admin_user` / `admin_pass` 等安全相关配置。

## 🔨 编译

### 本地编译

```bash
go mod tidy
go build -o opentalon .
```

### 交叉编译

```bash
# Linux amd64 通用静态版
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -tags netgo,osusergo -o dist/opentalon-linux-amd64 .

# Windows amd64
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/opentalon-windows-amd64.exe .

# Alpine / ARM64
GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o dist/opentalon-linux-arm64 .

# 或使用 Makefile
make all
```

> ✅ 纯 Go SQLite (`modernc.org/sqlite`) — 无 CGO，无需额外工具链即可交叉编译。

## 🌐 REST API

| Method | Path | 说明 |
|--------|------|------|
| `GET`  | `/api/devices/tree` | 获取完整树形拓扑 |
| `POST` | `/api/devices/register` | Agent 注册/更新设备 |
| `POST` | `/api/metrics` | Agent 上报指标 |
| `GET`  | `/api/devices/:id/metrics` | 获取某设备最新指标 |
| `GET`  | `/api/health` | 健康检查 |

## 🔑 SSH 运维任务

对无法部署 Agent 的设备，通过 SSH 执行预置任务：

- **`FixRPFilter`** — RockyLinux 路由黑洞修复（tun + enp6s18 的 rp_filter=0）
- **`UpdateFNOSScript`** — 更新 fnos_fix 脚本（自动跳过 V5.0 旧版本）
- **`PushSingBoxConfig`** — 推送 sing-box 1.12.16 配置至旁路由并重启（使用 `hosts.predefined` 语法）

## 📋 适配的异构系统

Windows 10 · Alpine Linux · Debian / FNOS · Proxmox VE · RockyLinux · Merlin 路由 · OpenWrt

## 📄 License

[MIT](LICENSE) © 2024 vesaa
