# 安全策略

## 报告安全问题

如果你发现了安全漏洞，**请不要在公开的 Issue 中报告**。

请通过以下方式私下报告：

- 使用 GitHub 的 [Security Advisory](https://github.com/snnabb/Meridian/security/advisories/new) 功能
- 或发送邮件至仓库维护者（见仓库 Profile）

我们会在收到报告后尽快确认并处理。

## 当前安全边界

以下是 Meridian 当前的安全设计和已知限制，请在部署前了解：

### 认证

- 管理面板使用 `HttpOnly`、`SameSite=Strict` 的 JWT 会话 Cookie；浏览器脚本无法读取会话令牌
- 密码使用 bcrypt 哈希存储
- 新管理员密码要求 12-72 字节
- JWT 使用 HMAC-SHA256 签名，会话有效期 72 小时
- `JWT_SECRET` 必须至少 32 字节；未设置时程序会生成进程级随机密钥（重启后旧 Token 全部失效）
- 一键脚本修改管理员密码时会原子轮换 `JWT_SECRET`，因此此前签发的所有 Token 会立即失效；密码只通过标准输入传给离线管理命令
- 首次创建管理员必须在启动前提供 `SETUP_TOKEN`；服务本身不会生成或记录令牌，创建成功后令牌会从进程内存清除。一键安装器会将随机令牌写入受保护的 `.env` 配置，以便管理员在完成初始化前恢复它，但不会将其写入服务日志
- 登录失败统一返回相同错误；同一来源连续失败 5 次后会被限制 15 分钟，记录会过期并在容量达到上限时按最近使用情况淘汰

### 单用户

- 当前只支持一个管理员账户
- 不支持多用户、角色划分或权限隔离
- 任何持有有效会话的请求都可以执行所有管理操作

### 网络

- 未配置域名时管理面板默认监听 `0.0.0.0`；一键脚本启用面板域名后会改为 `127.0.0.1`，只信任回环代理并由 Nginx 提供 HTTPS
- 管理面板本身不提供 HTTPS，需要外层反代处理 TLS 终止
- 站点支持 `host`、`port`、`both` 三种入口模式；推荐的 `host` 模式只使用共享 Host 路由，不绑定保留的高端口，并强制要求面板回环绑定或非空 `TRUSTED_PROXY_CIDRS` 来源白名单。面板非回环绑定时，伪造正确 Host 的非可信 peer 仍会被拒绝；`port` 和显式高风险的 `both` 独立端口仍绑定所有接口
- 设置 `PANEL_DOMAIN` 后，未知 Host 返回 `421` 而不是管理面板；未设置时保留直接 IP/任意 Host 的初始部署兼容行为
- 安装器生成的 Nginx 配置只代理管理端口，不读取或代理站点回源、播放地址或站点监听端口
- 管理 API 默认拒绝跨站浏览器请求；所有状态变更还要求同源 `Origin` 或 `Referer`，并发送 CSP、`X-Frame-Options`、`nosniff` 等响应头
- 管理端和站点代理端都配置了请求头超时、空闲超时及请求头大小上限

### 数据

- SQLite 数据库文件包含管理员密码哈希和站点配置；固定上游 Header 的名称以明文保存，值使用独立的 `UPSTREAM_HEADER_KEY` 通过 AES-GCM 加密
- 管理 API 对固定上游 Header 采用只写语义，不回显明文或数据库密文。`UPSTREAM_HEADER_KEY` 不得与 `JWT_SECRET` 共用，且必须随数据库一起备份
- **仅 Linux / macOS**：进程会使用 `0077` 文件掩码并将数据库、WAL、SHM 文件收紧为 `0600`
- **Windows**：不提供等价保证。`os.Chmod` 在 Windows 上只能切换 `FILE_ATTRIBUTE_READONLY`，无法表达"仅所有者可读"的 DACL，因此程序不会尝试收紧权限，而是在启动日志中给出警告。数据库会沿用所在目录的继承权限——请自行限制该目录的访问权限，尤其不要放在 `C:\` 下直接新建的目录中（这类目录默认允许 `BUILTIN\Users` 读取）
- 没有审计日志，操作不可追溯
- 当前频率限制只覆盖登录入口，不是通用 API 限流器

### 上游通信

- 与上游 Emby 服务器的通信基于配置的 URL scheme（HTTP 或 HTTPS）
- HTTPS/WSS 上游连接和 TLS 诊断都会校验证书链、有效期与主机名，并要求 TLS 1.2 或更高版本
- 代理会保留上游返回的 CSP 和 `X-Frame-Options` 等安全响应头
- 固定自定义 Header 只发送给主回源的精确 scheme、主机和有效端口；新密文的 AES-GCM 认证数据同时绑定 Header 名称和该 authority。修改主回源 authority 会在 HTTP 层和数据层清空未重新输入的旧 Header，独立播放回源及跨 authority 重定向也会删除这些 Header。Authorization、Cookie、Host、转发头和 hop-by-hop Header 不能由该功能覆盖
- Meridian 管理会话 Cookie 会在所有站点 HTTP 与 WebSocket 请求出站前单独剥离，其他上游业务 Cookie 保留；畸形 Cookie Header 按失败关闭策略整头删除
- 上游 HTTP 响应和 WebSocket 101 中名称精确为 `meridian_session` 的 `Set-Cookie` 会被删除，合法的 Emby/业务 Cookie 原样保留；无法安全解析的单条 `Set-Cookie` 按失败关闭策略丢弃
- 直连客户端提供的转发头会全部重建；只有 peer 命中 `TRUSTED_PROXY_CIDRS` 时才采纳单一、合法的 `X-Real-IP` 与 `http`/`https` 协议值，不会把任意 `X-Forwarded-For` 链传给上游
- 运行日志只保留上游的 scheme、主机和端口，不记录路径、查询参数或 URL 凭据

### 部署与供应链

- Release 附带 `SHA256SUMS`，安装脚本在替换二进制前强制校验 SHA-256
- 发布工作流会先严格校验标签格式，再将校验后的值传给构建和镜像步骤
- 更新与改密流程在修改前创建权限为 `0600` 的内部备份，并在健康检查失败时自动恢复
- systemd 服务和官方 Docker 镜像默认以非 root 用户运行
- CI 执行竞态测试、`go vet`、`govulncheck`、`gosec` 与 CodeQL

## 支持的版本

当前项目处于活跃开发阶段，安全修复仅针对最新版本。
