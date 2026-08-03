<div align="center">

# Meridian

轻量级 Emby 反向代理管理面板
单文件 Go 后端 + 嵌入式 SPA 前端，开箱即用

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![SQLite](https://img.shields.io/badge/SQLite-embedded-003B57?logo=sqlite&logoColor=white)](https://pkg.go.dev/modernc.org/sqlite)
[![CI](https://github.com/snnabb/Meridian/actions/workflows/ci.yml/badge.svg)](https://github.com/snnabb/Meridian/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://github.com/snnabb/Meridian/pkgs/container/meridian)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

## 界面预览

| 仪表盘 | 站点管理 | 故障诊断 |
|:---:|:---:|:---:|
| ![仪表盘](docs/dashboard.png) | ![站点管理](docs/sites.png) | ![故障诊断](docs/diagnostics.png) |

## 这是什么

Meridian 是一个专为 Emby 媒体服务器设计的反向代理管理面板（Emby reverse proxy management panel）。它解决的核心问题是：**当你需要在一台机器上管理多个 Emby 反代站点时，不想手写 Nginx 配置，不想逐个维护 UA 伪装规则，也不想自己实现流量计量和限速。**

Meridian 把这些事情打包成一个单二进制程序，带管理界面，带实时监控，开箱可用。

## 友链

- [NodeSeek](https://www.nodeseek.com/)
- [Linux.do](https://linux.do/)

## 核心特性

| 功能 | 说明 |
|------|------|
| **多站点反代** | 每个站点可选择 `host`、`port` 或 `both` 入口模式，并独立配置主回源与播放回源 |
| **共享域名入口** | 可为站点配置一个精确域名，通过面板入口按 Host 分流，兼容 Nginx/CDN 的标准 443 入口 |
| **双上游分流** | 网页/API 和播放/转码流量可分别指向不同上游 |
| **UA 伪装** | 预设（Infuse / Web / 客户端）、自定义固定身份或透传保留客户端身份；HTTP、WebSocket 与受限播放重定向统一改写或透传 |
| **加密上游请求头** | 为主回源添加固定自定义 Header；值加密存储、只写不回显，且不会转发到独立播放/CDN 域名 |
| **流量管控** | 按站点统计流量、设置限速、设置配额 |
| **WebSocket 代理** | 完整支持 Emby 的 WebSocket 通信 |
| **SSE 实时推送** | 仪表盘数据通过 Server-Sent Events 实时更新 |
| **故障诊断** | 回源健康检测、上游 TLS 证书检查、请求头预览 |
| **JWT 认证** | HttpOnly 会话 Cookie 认证，密码 bcrypt 存储 |
| **单二进制部署** | 前端嵌入二进制，SQLite 持久化，无外部依赖 |

---

## 快速部署

### Linux / macOS — 一键安装（适用于已发布版本）

一行命令进入精简菜单：安装、更新到最新版、修改管理员密码、卸载。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/snnabb/Meridian/master/install.sh)
```

> 首次安装从 GitHub Releases 下载最新二进制，并使用同一 Release 中的 `SHA256SUMS` 强制校验。systemd 部署默认使用独立的 `meridian` 非 root 用户。重复运行 `install` 不会更新程序，只用于补充或重新配置面板域名。
>
> 首次创建管理员需要安装结束时显示的初始化令牌。Linux 一键安装会将其保存在受保护的 `/opt/meridian/.env`；若在尚未创建管理员前遗失安装输出，可由服务器 root 用户从该文件恢复。重复运行 `install` 或 `update` 只会为旧配置补齐缺失令牌，不会轮换已有令牌。令牌等同于首次管理员创建权限，请勿贴到 Issue、日志或截图中。

也可以直接指定四个动作：

```bash
# 首次安装最新版；过程中可选择是否配置面板 HTTPS 域名
bash <(curl -fsSL https://raw.githubusercontent.com/snnabb/Meridian/master/install.sh) install

# 非交互配置面板域名（邮箱可省略）
bash <(curl -fsSL https://raw.githubusercontent.com/snnabb/Meridian/master/install.sh) install \
  --domain panel.example.com --email admin@example.com -y

# 更新：自动创建数据备份与一致性快照，保留上一版本；systemd 环境启动后健康检查，失败则自动回滚二进制和数据
bash <(curl -fsSL https://raw.githubusercontent.com/snnabb/Meridian/master/install.sh) update

# 隐藏输入两次新密码；同时轮换 JWT_SECRET，使全部旧令牌失效
bash <(curl -fsSL https://raw.githubusercontent.com/snnabb/Meridian/master/install.sh) password

# 卸载默认保留数据；只有显式添加 --purge 才删除数据
bash <(curl -fsSL https://raw.githubusercontent.com/snnabb/Meridian/master/install.sh) uninstall
```

选择配置域名时，脚本会安装或复用 Nginx、Certbot（支持 apt、dnf/yum、apk、pacman），申请证书并启用 HTTP→HTTPS。生成的配置只代理管理面板 `127.0.0.1:9090`（或自定义 `PORT`），不会读取或修改站点回源、播放地址、50001 或其他站点监听端口。macOS 可安装 Meridian，但不支持自动域名配置。

更新和改密会在内部自动创建一致性备份。在 systemd 环境中，更新还会执行健康检查，并在失败时自动回滚到上一版本二进制与升级前数据配置；非 systemd 环境会校验新二进制能否执行，但不会自动做完整健康检查。这些内部操作不再作为公开菜单命令。备份默认保存在 `/opt/meridian-backups`，权限为 `0600`，其中包含数据库和密钥，请按敏感文件保管。卸载默认保留数据和备份；`--purge` 才删除数据，并且不会删除 Nginx、Certbot 或证书。

### Docker

```bash
export MERIDIAN_SETUP_TOKEN="$(openssl rand -hex 32)"  # 保存此值，首次登录时需要输入
docker run -d --name meridian \
  --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --ulimit nofile=65536:65536 \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -p 127.0.0.1:9090:9090 -p 8001-8010:8001-8010 \
	-v meridian-data:/app/data \
	-e JWT_SECRET=$(openssl rand -hex 32) \
	-e UPSTREAM_HEADER_KEY=$(openssl rand -hex 32) \
	-e SETUP_TOKEN="$MERIDIAN_SETUP_TOKEN" \
	ghcr.io/snnabb/meridian:latest
```

> `8001-8010` 是反代站点监听端口范围，按实际需要调整。
>
> 管理面板默认只映射到宿主机 `127.0.0.1:9090`，建议再通过 HTTPS 反向代理访问。如果确实需要直接通过公网 IP 访问，可改成 `-p 9090:9090`，并同时配置防火墙白名单。
>
> 首次创建管理员前必须设置并妥善保存 `SETUP_TOKEN`；服务不会把它写入启动日志。上面的命令把随机值保存在 `MERIDIAN_SETUP_TOKEN` 中，请在关闭当前 shell 前记入密码管理器，以便在面板中输入。
>
> 官方镜像会在推送 `v*` 标签时由 GitHub Actions 构建并推送到 GHCR。若仓库尚未发布版本，或 GHCR 中暂时没有可用镜像，请改用源码构建。

### Windows

```powershell
Invoke-WebRequest -Uri "https://github.com/snnabb/Meridian/releases/latest/download/meridian-windows-amd64.exe" -OutFile "meridian.exe"
function New-MeridianSecret {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}
$env:JWT_SECRET = New-MeridianSecret
$env:UPSTREAM_HEADER_KEY = New-MeridianSecret
$env:SETUP_TOKEN = New-MeridianSecret
.\meridian.exe
```

> 密钥必须用密码学安全随机数生成。`Get-Random` 不够安全，不要用它生成 `JWT_SECRET`、`UPSTREAM_HEADER_KEY` 或 `SETUP_TOKEN`。若以前按旧命令生成过密钥，请重新生成并轮换 `JWT_SECRET`；已经保存固定上游 Header 后不要直接轮换 `UPSTREAM_HEADER_KEY`，否则旧密文无法解密，必须为所有相关站点重新配置 Header 值。
>
> Windows 二进制下载同样依赖 GitHub Releases。没有已发布版本时，请使用源码构建。


### 从源码构建

```bash
git clone https://github.com/snnabb/Meridian.git && cd Meridian
go build -o meridian .
JWT_SECRET=$(openssl rand -hex 32) UPSTREAM_HEADER_KEY=$(openssl rand -hex 32) SETUP_TOKEN=$(openssl rand -hex 32) ./meridian
```

未配置域名时访问 `http://你的IP:9090`；配置后访问对应的 `https://面板域名`。首次打开会要求输入管理员账号、12–72 字节的密码，以及安装完成时显示的初始化令牌。源码、Docker 和 Windows 部署必须在首次启动前显式设置 `SETUP_TOKEN`；服务本身不会自动生成或记录该值。

---

## 配置

### 命令行参数

```bash
./meridian                          # 默认 :9090，数据库在当前目录
./meridian --port 8080              # 自定义端口
./meridian --db /data/meridian.db   # 自定义数据库路径
read -r -s -p '新密码: ' ADMIN_PASSWORD; echo
printf '%s\n' "$ADMIN_PASSWORD" | ./meridian admin reset-password --db /data/meridian.db --password-stdin
unset ADMIN_PASSWORD
```

最后一个命令是供自动化使用的离线改密接口：密码只能从标准输入传入，数据库必须恰好有一个管理员。生产环境优先使用一键脚本的 `password` 操作，因为脚本还会停止服务、备份数据库、原子轮换 `JWT_SECRET`、重启并健康检查。

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PORT` | `9090` | 管理面板监听端口 |
| `DB_PATH` | `meridian.db` | SQLite 数据库路径 |
| `PANEL_BIND_ADDR` | `0.0.0.0` | 控制管理面板及共享 Host 入口的绑定地址；严格 `host` 模式要求回环地址，或配合非空 `TRUSTED_PROXY_CIDRS` 做入口来源白名单 |
| `PANEL_DOMAIN` | 空 | 管理面板的唯一允许域名；设置后未知 Host 返回 `421`，不再回退到面板 |
| `JWT_SECRET` | 进程启动时随机生成 | 至少 32 字节的 JWT 签名密钥。**生产环境必须显式设置**，否则每次重启后会话全部失效 |
| `UPSTREAM_HEADER_KEY` | 空 | 至少 32 字节的独立加密密钥；配置固定上游请求头时必需。丢失或轮换后，已有请求头无法解密；一键安装器会自动生成 |
| `SETUP_TOKEN` | 无 | 数据库中没有管理员时必须设置的初始化令牌；首次创建成功后仅从进程内存清除，服务不会记录其值 |
| `TRUSTED_PROXY_CIDRS` | 空 | 可信入口代理 CIDR，多个值用逗号分隔。Meridian 只采纳其规范化的 `X-Real-IP`/`X-Forwarded-Proto`，并在面板非回环绑定时把它同时作为严格 `host` 入口来源白名单；不要填写客户端网段或 `0.0.0.0/0` |

### Docker Compose

```yaml
services:
  meridian:
    image: ghcr.io/snnabb/meridian:latest
    restart: unless-stopped
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=16m
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
    ports:
      - "127.0.0.1:9090:9090"
      - "8001-8010:8001-8010"
    volumes:
      - meridian-data:/app/data
    environment:
      - JWT_SECRET=your-secret-here    # 替换为一个固定随机字符串
      - UPSTREAM_HEADER_KEY=your-other-secret-here # 与 JWT_SECRET 不同的固定随机字符串
      - SETUP_TOKEN=your-setup-token   # 首次启动前设置并妥善保存

volumes:
  meridian-data:
```

---

## 技术架构

```
                 Nginx / CDN :443
                         │ 保留原始 Host
┌────────────────────────▼─────────────────────────┐
│                    Meridian                      │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │       共享入口 / 管理面板 :9090            │  │
│  │  PANEL_DOMAIN ──► REST API / SSE / 静态文件 │  │
│  │  public_host  ──► 站点反代引擎 (host/both)  │  │
│  └───────────────────────────────────────────┘  │
│                         │                       │
│  :8001 / :8002 / :800N ─┤ 可选独立入口          │
│       (port/both)        │                       │
│                         ▼                       │
│  ┌───────────────────────────────────────────┐  │
│  │              每站点代理与策略              │  │
│  │  HTTP / WebSocket ──► target_url          │  │
│  │  播放流量         ──► playback_target_url │  │
│  └───────────────────────────────────────────┘  │
│                         │                       │
│  ┌──────────────────────▼────────────────────┐  │
│  │              SQLite（嵌入式）              │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

| 组件 | 技术选型 |
|------|---------|
| 后端 | 单文件 Go（`main.go`），标准库 `net/http` |
| 前端 | 原生 HTML/CSS/JS SPA，hash 路由，`embed.FS` 嵌入 |
| 数据库 | `modernc.org/sqlite`（纯 Go，无 CGO） |
| 认证 | 自实现 HMAC-SHA256 JWT |

### 项目结构

```
Meridian/
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
    ├── ci.yml            # Push / PR 校验：测试 + 编译
    └── release.yml       # Tag 发布：多平台构建 + Docker 推送 + Release
```

---

## 双上游配置

每个站点可以配置两个上游地址：

| 字段 | 用途 | 示例 |
|------|------|------|
| **回源地址**（`target_url`） | 网页、API、元数据 | `https://emby.example.com` |
| **播放地址**（`playback_target_url`） | 播放、转码、直链下载 | `https://cdn.example.com` |

播放地址为可选项。不设置时所有请求走同一上游。当前可手工填写最多 128 个播放 authority：第一个是实际播放回源，其余只在 `redirect` 模式中作为允许跟随的重定向白名单；`direct` 模式不会轮询、负载均衡或自动故障转移。本阶段尚不从 Emby 响应中自动发现后端。

地址没有写协议时，Meridian 会把 `域名:443`（也兼容中文全角冒号 `：443`）识别为 HTTPS；其他端口仍默认按 HTTP 处理。HTTPS 使用非 443 端口时请明确写成 `https://域名:端口`。重定向模式会把 `https://域名:443` 和省略默认端口的 `https://域名` 视为同一播放回源。

如果上游实际部署在子路径下，可以直接填写完整基础路径，例如 `https://emby.example.com/emby`；Meridian 会把客户端请求路径安全地拼接到该基础路径。重定向播放模式只会跟随 GET/HEAD 播放请求，并要求重定向目标的协议、域名和端口与已配置播放回源一致，不会把 HTTPS 自动降级到 HTTP。

设置后以下路径会路由到播放上游：
`/Videos/`、`/emby/Videos/`、`/Audio/`、`/emby/Audio/`、`/LiveTV/`、`/emby/LiveTV/`、`/Items/.../Download`

**典型场景**：Emby 主服务器负责 API 和元数据，CDN 或专用媒体服务器负责大文件分发。

### 共享域名入口

每个站点有三种入口模式：`host`（仅共享域名，推荐）、`port`（仅独立端口）和 `both`（共享域名与独立端口同时启用）。`host` 模式只在面板监听地址上按 `public_host` 分流，不会绑定站点的保留端口；`both` 才会额外监听该高端口。当 Nginx、Cloudflare Tunnel 或其他可信入口保留原始 `Host` 时，Meridian 会把这个域名除下述保留命名空间外的路径转给对应站点。

严格 `host` 模式必须满足以下一项：`PANEL_BIND_ADDR` 是回环地址（推荐，同机 Nginx），或配置非空 `TRUSTED_PROXY_CIDRS`。后一种适用于 Docker 网络/外置入口：共享站点只接受这些 peer CIDR 的请求，直接访问源站 IP 并伪造 `Host` 会返回 `403`。不要把公网客户端网段、容器默认大网段或 `0.0.0.0/0` 当作可信代理；否则等同于取消这层防绕过保护。`both` 是显式高风险兼容模式，独立端口仍需防火墙保护。

设置 `PANEL_DOMAIN` 后，只有精确的面板域名能够进入管理界面，未知域名或 IP Host 返回 `421 Misdirected Request`；已配置但停用的站点返回 `503`，都不会回退并暴露管理面板。未设置 `PANEL_DOMAIN` 时继续支持直接 IP 访问，方便初始部署。

`public_host` 使用精确、大小写不敏感的 DNS 名称匹配。它不接受协议、端口、路径、IP 或通配符，也不能与 `PANEL_DOMAIN` 相同。当前版本不支持路径前缀部署，因为 Emby 的绝对路径、播放 URL 和 WebSocket 端点需要完整的 base-path 协议设计，不能只做字符串裁剪。

`/_meridian/d` 及其子路径保留给后续签名动态播放路由，当前版本固定返回不可缓存的 `410 Gone`，不会转发到任何上游。若现有 Emby 插件或自定义接口正在使用这个命名空间，升级前必须迁移路径；本阶段尚未实现动态后端自动识别。

反向代理必须保留 Host，并把普通 HTTP 与 WebSocket 都转到同一个 Meridian 面板端口。同机 Nginx 建议同时设置 `PANEL_BIND_ADDR=127.0.0.1` 和 `TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128`；前者关闭公网直连，后者让 Meridian 只从本机代理采纳规范化的 `X-Real-IP`。若缺少后者，所有远程登录会共用 Nginx 的回环地址作为限流身份，任一来源都可能触发共享锁定。例如：

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    server_name emby.example.com;

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        client_max_body_size 0; # 或改成符合你上传策略的明确上限
    }
}
```

Meridian 只接受可信代理提供的单值 `X-Real-IP`，不会从可能包含客户端伪造内容的 `X-Forwarded-For` 链选择身份。Docker、Cloudflare Tunnel 或外置 Nginx 应把 `TRUSTED_PROXY_CIDRS` 精确设为实际代理 peer 网段，不能使用 `0.0.0.0/0`。Meridian 不负责为站点域名申请证书或修改 CDN DNS；证书、Cloudflare SSL 模式、防火墙和源站只允许可信入口访问等设置仍由入口层管理。上例的长超时、关闭缓冲和上传上限是流媒体/长连接所需；如果已有全局策略，可以按等价配置调整。

> 新建共享域名站点默认使用 `host`，这是避免绕过 CDN 的推荐配置；程序会拒绝在“非回环绑定且没有可信代理来源”的条件下启用它。只有确实需要兼容直接端口访问时才选择 `both`，并用防火墙限制来源；`port` 和 `both` 的独立端口都会绑定所有网络接口。

### 固定上游请求头

每个站点可以为主回源配置最多 16 个固定 Header。所有新值都使用 `UPSTREAM_HEADER_KEY` 通过 AES-GCM v2 加密后写入 SQLite，认证数据同时绑定 Header 名称与目标 scheme/主机/有效端口；管理 API 和浏览器只返回 Header 名称与“已配置”状态，不会回显明文或密文。同一主回源 authority 内编辑时值留空表示保留，删除整行才会移除；一旦修改协议、域名或有效端口，旧值会自动清空，必须重新输入，避免把源站秘密带到新主机。

这些 Header 只会发送给 `target_url` 的精确协议、域名和有效端口。独立播放回源、WebSocket 播放目标和跨 authority 重定向都会主动删除它们，避免把源站秘密带给 CDN。`Authorization`、`Cookie`、`Host`、`User-Agent`、`X-Forwarded-*`、常见供应商客户端 IP Header、Emby 授权头和 WebSocket/hop-by-hop Header 由 Meridian 管理，不能在这里覆盖。

> `UPSTREAM_HEADER_KEY` 必须与数据库一起备份并保持不变。不要与 `JWT_SECRET` 共用同一个值；丢失该密钥后，包含加密 Header 的站点会拒绝启动，而不是静默发送空值。

### UA 身份模式

每个站点可选 Infuse、Web、客户端三个预设，或选择“自定义”固定身份，或选择“透传”保留客户端身份。

- **自定义（固定身份）**：填写 `User-Agent`、Emby `Client`、`Version`，Meridian 会在普通 HTTP、WebSocket 以及受配置白名单约束的播放重定向请求中统一改写成这套固定值，所有请求保持一致；`Device` 与 `DeviceId` 会原样保留。为避免请求头注入和 Emby 授权头格式损坏，自定义值只接受受限长度的可打印 ASCII 字符，`Client` 和 `Version` 不接受引号或反斜杠。
- **透传（每请求真实身份）**：Meridian 不生成也不改写任何 UA 身份，每个请求原样保留客户端自带的 `User-Agent` 与 Emby `Client`、`Version`、`Device`、`DeviceId` 后转发，适合多用户共用一个反代站点、需要按客户端区分身份的部署。

两种模式的凭据安全边界一致：站点请求出站前始终删除 Meridian 管理会话 `meridian_session`，但保留 Emby 自己的 Cookie；跨 authority 转发时 `Cookie`、`Authorization` 等凭据仍会被剥离，`X-Forwarded-*` 与 hop-by-hop 请求头清洗保持不变，透传不会绕过任何凭据清洗。

---

## 诊断功能说明

| 检测项 | 检测对象 | 含义 | 不代表什么 |
|--------|---------|------|-----------|
| **主回源健康** | 上游 `target_url` | 网络层可达性与探针结果（多探针路径，401/403/404 仍算在线；元数据接口不可用时会回退到目标根路径探针） | 不是端到端的完整业务可用性证明 |
| **播放回源健康** | `playback_target_url` 的实际生效上游 | 基于播放类路径的轻量探针结果（默认使用轻量请求，不做完整媒体拉流） | 不代表媒体链路一定可正常播放 |
| **主回源 TLS** | 主回源 HTTPS 站点证书 | 证书有效期、颁发机构展示 | 不是 Meridian 自己监听端口的证书 |
| **播放回源 TLS** | 播放回源 HTTPS 站点证书 | 仅在播放回源为独立 HTTPS 上游时单独展示 | 不负责自动签发或续期 |
| **请求头配置** | 本地 UA 配置 | 代理将发送给上游的 UA / Client / Version 值 | 不是远端回显验证 |
| **代理状态** | 本地反代进程 | 是否运行、监听端口 | — |

当 `playback_target_url` 为空时，诊断页会明确标记“播放回源回退到主回源”；当它与 `target_url` 相同时，诊断页会复用主回源结果而不重复展示完全相同的诊断块。
播放回源健康会额外展示当前轻量探针的方法、目标 URL 和返回状态，帮助区分“播放路径可达”与“完整播放成功”这两个不同概念。

---

## 运维要点

- **JWT 密钥**：未设置 `JWT_SECRET` 时每次启动生成随机密钥，重启后会话全部失效
- **上游 Header 密钥**：使用固定请求头时必须长期保留 `UPSTREAM_HEADER_KEY`；它应与 JWT 密钥分开生成和备份
- **首次初始化**：数据库中没有管理员时必须预先配置 `SETUP_TOKEN`，创建操作在数据库中原子执行，服务不会记录令牌
- **登录保护**：同一来源在 15 分钟内连续失败 5 次后会被暂时限制 15 分钟；限流记录会过期并在容量达到上限时按最近使用情况淘汰
- **浏览器边界**：管理 API 使用 `HttpOnly`、`SameSite=Strict` 会话 Cookie，只允许同源的状态变更请求，并发送 CSP、防嵌入和 MIME 嗅探保护头
- **流量持久化**：每 60 秒刷入 SQLite，异常退出可能丢失最近一分钟计量
- **操作原子性**：站点创建/启停/更新如反代绑定失败，会回滚数据库并返回错误
- **优雅关闭**：收到 `SIGINT`/`SIGTERM` 后先 flush 流量再退出

---

## 验证 & CI/CD

```bash
go test -race ./...                                  # 运行测试和竞态检测
go vet ./...                                          # Go 静态检查
govulncheck ./...                                     # 已知漏洞检查
gosec -severity medium -confidence medium ./...       # 安全规则检查
go build -trimpath -buildvcs=false -o meridian .      # 编译
```

日常 push / pull request 会自动触发：

- 模块校验、竞态测试、`go vet`
- `govulncheck`、`gosec`、CodeQL
- 前端 JavaScript 与安装脚本语法检查
- 可复现路径裁剪构建

推送 `v*` 标签时自动触发：
- 多平台构建（linux/amd64、linux/arm64、windows/amd64、darwin/amd64、darwin/arm64）
- 创建 GitHub Release 并上传二进制
- 生成并上传 `SHA256SUMS`
- 构建并推送 linux/amd64、linux/arm64 多架构 Docker 镜像到 `ghcr.io`

---

## V1 定位

Meridian `v1` 明确定位为一个**单管理员、轻量、可直接落地**的 Emby reverse proxy management panel。

- 保留：登录、站点 CRUD、启停、UA 改写、流量统计、双上游、结构化诊断
- 不做：多用户、角色权限、审计日志、Telegram / Webhook 通知
- 目标：先把单文件 Go + 嵌入式 SPA 的简单面板体验收口，而不是提前引入更重的管理系统

## 升级现有实例

升级时建议优先保持这些内容不变：

- `JWT_SECRET`
- `UPSTREAM_HEADER_KEY`
- SQLite 数据库文件及其同目录的 `-wal` / `-shm`

使用一键脚本执行 `update` 时，下列步骤会自动完成；手动部署时推荐：

1. 停止正在运行的 Meridian 服务。
2. 备份当前二进制、数据库文件以及保存 `JWT_SECRET`、`UPSTREAM_HEADER_KEY` 的环境配置。
3. 替换为新版本二进制或新镜像。
4. 用原来的 `JWT_SECRET`、`UPSTREAM_HEADER_KEY` 和数据库重新启动。
5. 登录面板后检查站点列表、端口监听和诊断页。

如果升级后临时忘记保留 `JWT_SECRET`，历史 JWT 会全部失效，表现为所有登录状态需要重新建立。

## 备份与恢复

一键脚本不再公开单独的备份命令。执行 `update` 或 `password` 时会自动短暂停止 systemd 服务并在 `/opt/meridian-backups` 创建一致性备份；如需自定义备份策略，请在停止 Meridian 后备份下列最小文件集。

最小备份集：

- `meridian.db`
- `meridian.db-wal`
- `meridian.db-shm`
- 保存 `JWT_SECRET` 和 `UPSTREAM_HEADER_KEY` 的 `.env`、systemd 环境文件或容器环境配置

恢复步骤：

1. 停止 Meridian。
2. 还原数据库文件到原路径。
3. 还原原来的 `JWT_SECRET` 和 `UPSTREAM_HEADER_KEY`。
4. 启动 Meridian。
5. 验证管理员登录、站点配置和关键代理端口。

如果你使用 Docker，恢复时同样要保留挂载卷里的数据库文件，并继续使用原来的 `JWT_SECRET` 和 `UPSTREAM_HEADER_KEY`。

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
- 管理面板本身不终止 TLS，公网部署必须放在 HTTPS 反向代理之后
- 共享入口仅支持精确 Host，不支持通配符或 URL 路径前缀
- TLS 诊断会验证上游证书，但不负责证书签发和续期
- UA 诊断是本地配置预览，不验证远端实际收到的请求头

## 开发须知

- 后端代码保持在 `main.go`，不拆分文件
- 前端使用 hash 路由（`#/dashboard`、`#/sites`、`#/diagnostics`）
- API 认证使用 HttpOnly JWT 会话 Cookie
- SQLite 驱动名为 `sqlite`（不是 `sqlite3`）
- 静态资源通过 `go:embed` 嵌入二进制

## 参与贡献

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 安全问题

请参阅 [SECURITY.md](SECURITY.md)。

## License

MIT
