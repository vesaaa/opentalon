# OpenTalon

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

```bash
# Linux amd64
curl -L https://github.com/vesaa/opentalon/releases/latest/download/opentalon-linux-amd64 -o opentalon
chmod +x opentalon

# Windows amd64 (PowerShell)
Invoke-WebRequest -Uri "https://github.com/vesaa/opentalon/releases/latest/download/opentalon-windows-amd64.exe" -OutFile opentalon.exe
```

### 启动 Server

```bash
./opentalon server
# Dashboard: http://localhost:9090
```

### 纳管设备（Agent）

```bash
# 在需要被管理的设备上运行：
./opentalon agent --join 192.168.1.1

# 指定分组和 PVE 父节点（可选）：
./opentalon agent --join 192.168.1.1 --group "虚拟化" --parent 3
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
server_host:     "0.0.0.0"
server_port:     9090
db_path:         "opentalon.db"
main_router_ip:  "192.168.1.1"
side_router_ip:  "192.168.1.2"
agent_interval_seconds: 30
agent_group:     "default"
agent_network_mode: "Bridged"
```

## 🔨 编译

### 本地编译

```bash
go mod tidy
go build -o opentalon .
```

### 交叉编译

```bash
# Linux amd64
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/opentalon-linux-amd64 .

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
