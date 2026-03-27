<div align="center">

# Meridian

轻量级 Emby 反向代理管理面板
单文件 Go 后端 + 嵌入式 SPA 前端，开箱即用

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![SQLite](https://img.shields.io/badge/SQLite-embedded-003B57?logo=sqlite&logoColor=white)](https://pkg.go.dev/modernc.org/sqlite)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://github.com/snnabb/meridian/pkgs/container/meridian)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

## 界面预览

| 仪表盘 | 站点管理 | 故障诊断 |
|:---:|:---:|:---:|
| ![仪表盘](docs/dashboard.png) | ![站点管理](docs/sites.png) | ![故障诊断](docs/diagnostics.png) |

## 这是什么

Meridian 是一个专为 Emby 媒体服务器设计的反向代理管理面板（Emby reverse proxy management panel）。它解决的核心问题是：**当你需要在一台机器上管理多个 Emby 反代站点时，不想手写 Nginx 配置，不想逐个维护 UA 伪装规则，也不想自己实现流量计量和限速。**

Meridian 把这些事情打包成一个单二进制程序，带管理界面，带实时监控，开箱可用。

## 核心特性

| 功能 | 说明 |
|------|------|
| **多站点反代** | 每个站点独立监听端口，独立配置上游地址 |
| **双上游分流** | 网页/API 和播放/转码流量可分别指向不同上游 |
| **UA 伪装** | 3 种预设（Infuse / Web / 客户端），HTTP + WebSocket 统一改写 |
| **流量管控** | 按站点统计流量、设置限速、设置配额 |
| **WebSocket 代理** | 完整支持 Emby 的 WebSocket 通信 |
| **SSE 实时推送** | 仪表盘数据通过 Server-Sent Events 实时更新 |
| **故障诊断** | 回源健康检测、上游 TLS 证书检查、请求头预览 |
| **JWT 认证** | Bearer Token 认证，密码 bcrypt 存储 |
| **单二进制部署** | 前端嵌入二进制，SQLite 持久化，无外部依赖 |

---

## 快速部署

### Linux / macOS — 交互式安装（推荐）

一行命令，自动检测平台、下载最新版、配置 systemd 服务：

```bash
bash <(curl -sL https://raw.githubusercontent.com/snnabb/meridian/master/install.sh)
```

脚本支持三个操作：**安装**、**更新**（再跑一次即可）、**卸载**。也可以直接指定动作：

```bash
# 直接安装/更新
bash <(curl -sL https://raw.githubusercontent.com/snnabb/meridian/master/install.sh) install

# 直接卸载
bash <(curl -sL https://raw.githubusercontent.com/snnabb/meridian/master/install.sh) uninstall
```

### Docker

```bash
docker run -d --name meridian \
  -p 9090:9090 -p 8001-8010:8001-8010 \
  -v meridian-data:/app/data \
  -e JWT_SECRET=$(openssl rand -hex 32) \
  ghcr.io/snnabb/meridian:latest
```

> `8001-8010` 是反代站点监听端口范围，按实际需要调整。

### Windows

```powershell
Invoke-WebRequest -Uri "https://github.com/snnabb/meridian/releases/latest/download/meridian-windows-amd64.exe" -OutFile "meridian.exe"
$env:JWT_SECRET = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
.\meridian.exe
```

### 从源码构建

```bash
git clone https://github.com/snnabb/meridian.git && cd meridian
go build -o meridian .
JWT_SECRET=$(openssl rand -hex 32) ./meridian
```

部署完成后访问 `http://你的IP:9090`，首次打开会引导设置管理员密码。

---

## 配置

### 命令行参数

```bash
./meridian                          # 默认 :9090，数据库在当前目录
./meridian --port 8080              # 自定义端口
./meridian --db /data/meridian.db   # 自定义数据库路径
```

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PORT` | `9090` | 管理面板监听端口 |
| `DB_PATH` | `meridian.db` | SQLite 数据库路径 |
| `JWT_SECRET` | 进程启动时随机生成 | JWT 签名密钥。**生产环境必须显式设置**，否则每次重启后会话全部失效 |

### Docker Compose

```yaml
services:
  meridian:
    image: ghcr.io/snnabb/meridian:latest
    restart: unless-stopped
    ports:
      - "9090:9090"
      - "8001-8010:8001-8010"
    volumes:
      - meridian-data:/app/data
    environment:
      - JWT_SECRET=your-secret-here  # 替换为一个固定随机字符串

volumes:
  meridian-data:
```

---

## 技术架构

```
┌─────────────────────────────────────────────┐
│                 Meridian                      │
│                                              │
│  ┌──────────┐   ┌──────────────────────────┐ │
│  │ 管理面板  │   │     反代引擎 (per-site)   │ │
│  │ :9090    │   │  :8001  :8002  :800N     │ │
│  │          │   │                          │ │
│  │ REST API │   │  HTTP ──► target_url     │ │
│  │ SSE 推送 │   │  WS   ──► target_url     │ │
│  │ 静态文件  │   │  播放  ──► playback_url   │ │
│  └──────────┘   └──────────────────────────┘ │
│       │                     │                │
│  ┌──────────────────────────────────────┐    │
│  │            SQLite (嵌入式)            │    │
│  └──────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

| 组件 | 技术选型 |
|------|---------|
| 后端 | 单文件 Go（`main.go`），标准库 `net/http` |
| 前端 | 原生 HTML/CSS/JS SPA，hash 路由，`embed.FS` 嵌入 |
| 数据库 | `modernc.org/sqlite`（纯 Go，无 CGO） |
| 认证 | 自实现 HMAC-SHA256 JWT |

### 项目结构

```
meridian/
├── main.go              # 全部后端逻辑（API、反代引擎、诊断、认证）
├── main_test.go
├── web/
│   ├── embed.go          # Go embed 入口
│   └── static/
│       ├── index.html    # SPA 入口
│       ├── css/          # 样式
│       └── js/           # 前端逻辑（按页面拆分）
├── Dockerfile            # 多阶段构建
├── go.mod / go.sum
└── .github/workflows/
    └── release.yml       # CI：多平台构建 + Docker 推送 + Release
```

---

## 双上游配置

每个站点可以配置两个上游地址：

| 字段 | 用途 | 示例 |
|------|------|------|
| **回源地址**（`target_url`） | 网页、API、元数据 | `https://emby.example.com` |
| **播放地址**（`playback_target_url`） | 播放、转码、直链下载 | `https://cdn.example.com` |

播放地址为可选项。不设置时所有请求走同一上游。

设置后以下路径会路由到播放上游：
`/Videos/`、`/emby/Videos/`、`/Audio/`、`/emby/Audio/`、`/LiveTV/`、`/emby/LiveTV/`、`/Items/.../Download`

**典型场景**：Emby 主服务器负责 API 和元数据，CDN 或专用媒体服务器负责大文件分发。

---

## 诊断功能说明

| 检测项 | 检测对象 | 含义 | 不代表什么 |
|--------|---------|------|-----------|
| **回源健康** | 上游 `target_url` | 网络层可达性（多探针路径，401/403/404 仍算在线） | 不是端到端的业务健康证明 |
| **TLS 状态** | 上游 HTTPS 证书 | 证书有效期、颁发机构展示 | 不负责自动签发或续期 |
| **请求头配置** | 本地 UA 配置 | 代理将发送给上游的 UA / Client 值 | 不是远端回显验证 |
| **代理状态** | 本地反代进程 | 是否运行、监听端口 | — |

---

## 运维要点

- **JWT 密钥**：未设置 `JWT_SECRET` 时每次启动生成随机密钥，重启后会话全部失效
- **流量持久化**：每 60 秒刷入 SQLite，异常退出可能丢失最近一分钟计量
- **操作原子性**：站点创建/启停/更新如反代绑定失败，会回滚数据库并返回错误
- **优雅关闭**：收到 `SIGINT`/`SIGTERM` 后先 flush 流量再退出

---

## 验证 & CI/CD

```bash
go test ./...           # 运行测试
go build -o meridian .  # 编译
```

推送 `v*` 标签时自动触发：
- 多平台构建（linux/amd64、linux/arm64、windows/amd64、darwin/arm64）
- 创建 GitHub Release 并上传二进制
- 构建并推送 Docker 镜像到 `ghcr.io`

---

## Roadmap

以下功能尚未实现，列在这里作为未来方向：

- [ ] 多用户 + 角色权限
- [ ] 审计日志
- [ ] Telegram / Webhook 通知

## 限制与注意事项

- 当前只支持单管理员，不支持多用户或角色划分
- 没有审计日志，操作不可追溯
- 没有内置通知能力（无 Telegram / Webhook 集成）
- TLS 诊断是只读展示，不管证书签发和续期
- UA 诊断是本地配置预览，不验证远端实际收到的请求头

## 开发须知

- 后端代码保持在 `main.go`，不拆分文件
- 前端使用 hash 路由（`#/dashboard`、`#/sites`、`#/diagnostics`）
- API 认证使用 JWT Bearer Token
- SQLite 驱动名为 `sqlite`（不是 `sqlite3`）
- 静态资源通过 `go:embed` 嵌入二进制

## 参与贡献

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 安全问题

请参阅 [SECURITY.md](SECURITY.md)。

## License

MIT
