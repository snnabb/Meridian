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
- `DYNAMIC_ROUTE_KEY` 是独立的动态路由主密钥，不得与 `JWT_SECRET` 或 `UPSTREAM_HEADER_KEY` 共用，且必须随数据库一起备份；管理 API 只返回“已配置”状态，不返回密钥。它用于 AES-GCM 加密并认证动态 capability；轮换或丢失后，正在使用的 capability 会失效。密钥为空不会阻止旧代理或关闭该功能的站点启动，但管理 API 拒绝新开启自动发现；数据库中已有的启用策略可以加载，动态目标会因运行能力不可用而失败关闭
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

### 自动播放后端发现

- 功能按站点启用；创建 API 省略开关时，仅在独立 `DYNAMIC_ROUTE_KEY` 已配置后默认开启，显式关闭保持关闭，缺钥匙时显式开启返回 `400`。完整默认来源为 Safe=`redirect,playback_info`、Compatible/Extreme=`redirect,playback_info,hls,dash`。新提交只接受完整默认集合或仅移除 `playback_info` 的规范集合；`redirect` 不可关闭，Compatible/Extreme 的 HLS/DASH 也不可关闭。省略来源的新策略、profile 变化或 false→true 采用完整集合；已启用旧版任意子集只可在同 profile 的无关更新中完全不变地保留。管理 UI 的“解析 PlaybackInfo”默认开启；关闭时不解析或改写 PlaybackInfo 正文，也不签发其中外部 URL 的 capability。HTTP 30x 和其他 profile 固定来源继续工作；动态跟随后的最终响应仍执行 Header 白名单、安全头重建、trailer 删除和错误正文清洗，因此外部 URL 可能直接到达客户端。Safe/Compatible 不扫描未知 JSON 字段；Extreme 只在 PlaybackInfo 根和 MediaSource 子树内识别“整个字符串就是绝对 HTTP(S) URL”的值，不扫描 key、prose 子串、HTML、JavaScript、RequiredHttpHeaders 值或任意响应，也不接受客户端提供的 target
- Safe/Compatible 的 HTTP 30x 只对非 WebSocket GET/HEAD 已知播放路径处理 301/302/307/308。Extreme 才允许除 CONNECT、Upgrade 与保留 capability 路径外的任意数据面方法/路径，并处理 303；301/302 POST 与 303（HEAD 除外）转 GET，307/308 和其他方法保留语义。需要保留正文时必须有 profile 范围内的明确正长度、无 transfer/trailer，并在全局/每站解析内存与并发预算内预先建立可重复 reader；否则以 `redirect_body_replay_denied` 失败。上游因此可能把正文导向经过全部 target 校验的公网 authority，属于 Extreme 显式高风险边界
- PlaybackInfo 仅在站点开关开启时进入结构化解析；关闭时不读取或改写正文，也不签发 capability。未发生动态 30x 跟随时，结构化解析器不改变响应 Header；动态跟随后的最终响应仍保留跨 authority Header 清洗、安全头、trailer 删除和错误正文清洗。开启时，严格路径继续只改写经过审核的 MediaSource/MediaStream URL 字段；Extreme 才接受 MediaSources/MediaStreams/MediaAttachments 的 stringified array/object、让完整绝对 HTTP(S) Path 优先于 File/冲突 Protocol，并递归改写限定子树内的 whole-string URL。Extreme RequiredHttpHeaders 只允许 Accept/Accept-Language/Origin/Referer/User-Agent、8 项/4 KiB，规范化后写入 AEAD claim 并绑定精确 target；禁止 Cookie/Authorization/Host/Emby token/Forwarded/hop-by-hop，禁止 fixed Header 冲突、suffix/query/template 和 redirect/cross-authority 传播；同 authority 清单子资源必须重新签发精确 capability。HLS 的严格路径只处理已审核 URI；Extreme 才允许有界本地 EXT-X-DEFINE 替换和安全未知 EXT-X 标签/URI 属性，仍拒绝未识别 URL、DRM/key/license、Content Steering 与 interstitial 主动网络结构。DASH 的严格路径拒绝 DRM/foreign namespace；Extreme 可保留经过递归主动网络筛查的惰性 foreign wrapper 与 ContentProtection/cenc/mspr 元数据，PSSH/PRO 先有界 base64 解码再扫描 URL；DTD/entity、xlink、xml:base、PatchLocation、ImportedMPD、Metrics/Reporting、Content Steering、DVB font、license/foreign active URL 一律拒绝
- 外部目标改写为同源 `/_meridian/d/<capability>`；HLS/DASH 指向已配置回源的 URL 也使用绑定该 authority 并复用既有 transport/UA/Header 规则的 capability。capability 通过 AES-GCM 绑定站点、策略修订、来源、资源类型、清单深度、完整目标 path/query、时间、DASH client/server template 值，以及可选的规范化 RequiredHttpHeaders，只接受 GET/HEAD；Header claim 禁止 suffix/query/template 且 target 必须完全一致。清单新目标最多递归 3 层，认证为 resource 的 key/segment 只在正向 HLS/DASH MIME 或 active content 时失败关闭，`application/octet-stream` 与 manifest 后缀不会覆盖认证 resource kind。一次改写产生或复用的 token 以引用计数 provisional 状态存在，完整改写和父 capability 复核成功后才发布，失败则原子释放 capability 和未提交 authority；并发改写不会相互删除仍在使用的 token。篡改、每次 lookup 精确判定的 idle/绝对过期、跨站点、旧策略、错误资源类型/方法/路径/Header 绑定统一返回不可缓存且不含细节的 404。相同 target 与 Header 绑定在有效期内复用稳定 token，registry 同时受 64 MiB/站点、256 MiB/进程的字节预算与全局节流清理约束；站点停止/重载会撤销该实例内全部 token
- Profile 网络边界：新 Safe 配置始终启用 30x、可选择 PlaybackInfo，且仅 HTTPS:443，3 跳、256 authority、16 个 DNS 回答、每分钟 60 个新 authority、32 条动态流；新 Compatible 配置固定保留 30x/HLS/DASH、可选择 PlaybackInfo，为 HTTP(S) 任意端口，5/1024/32/300/128；新 Extreme 配置固定保留 30x/HLS/DASH、可选择 PlaybackInfo，为 10/4096/64/1200/512。三档协议正文上限为 4/16/64 MiB、active capability 为 4,096/16,384/65,536，绝对寿命为 8 小时/24 小时/7 天；结构化解析还取 8 MiB 输入、16 MiB 输出硬上限和 profile 上限中的最小值，并预留输入、对象树与输出的完整工作集。全进程还限制 16,384 authority、131,072 capability、256 MiB capability registry、1,024 动态流、每分钟 2,400 新 authority、32 DNS worker、8 并发解析和 256 MiB 解析内存；每站同时最多解析 2 个响应、capability registry 与解析内存各最多 64 MiB
- Safe 空规则表示允许受识别公共后缀约束的公网 DNS 主机名；存在规则时 exact/suffix 以并集收窄，suffix 只在 DNS 标签边界匹配。Safe 无论规则是否为空都独立拒绝 IP literal、只允许 HTTPS:443，并要求 `dynamic_allow_https_downgrade=false`。Compatible/Extreme 仍只允许公网目标；私网目标、自定义 CA、跳过 TLS 验证和 raw fallback 不可用
- 认证后的 profile catalog 公布每档完整默认来源、完整 `default_policy` 和 `empty_rules_semantics=public_dns_https_443`；显式来源只接受完整集合或仅移除 `playback_info` 的规范集合。`rollback_readiness` 只汇总已启用 Safe/空规则行及已启用非完整来源集合的数量，不返回站点名、目标或 URL；历史字段 `enabled_legacy_source_subsets` 也会统计关闭 PlaybackInfo 产生的规范集合。从 v1.9 回滚 v1.8 前必须先让 `enabled_safe_empty_rules` 归零（添加 v1.8 所需规则或关闭发现），并恢复匹配 v1.8 的升级前数据库备份；仅替换二进制可能触发 v1.8 启动校验失败
- 动态 URL 最长 4096 字节，只允许无 userinfo、fragment、空白/控制字符的绝对 HTTP(S)。全部 A/AAAA 都必须是允许的全球单播；混入私网、回环、链路本地、CGNAT、metadata、文档、保留、组播、转换或已知自身目标即整组拒绝。配置快照中的本机 IP 永久拒绝，并在 DNS 结果、transport 构造和每次 pinned dial 前重新枚举当前 interface；枚举失败关闭，运行时新增的公网 interface IP 不会穿透旧快照。校验后的 IP 固定到本次直拨 transport，不使用环境代理或二次 DNS；TLS 保留原 Host/SNI、验证系统证书链并要求 TLS 1.2 以上
- 普通跨未知 authority 只重建 Accept/Accept-Encoding/Range/If-Range 与固定 UA；Extreme 重放正文时可额外携带 Content-Type/Encoding/Language/MD5/Digest。Cookie、Authorization、Emby token Header、固定上游 Header、转发头、hop-by-hop 和其他自定义 Header 不会跨域；PlaybackInfo RequiredHttpHeaders 是独立精确-target AEAD 绑定，不进入 redirect Header。绑定管理员配置 authority 的 capability 复用普通主代理的管理 Cookie 剥离、可信转发头、UA 与固定 Header 策略；独立播放 authority 仍走跨域清洗。动态响应只保留 Content/Range 白名单，删除 Set-Cookie/trailer，强制 private/no-store、no-referrer、nosniff，并以 CSP sandbox/X-Frame-Options 阻断同源 active content。正文改写会删除失效的编码、长度、Range 和 validator Header，并限制读取时长、token/行/节点和改写输出
- 策略、解析、DNS、拨号或 TLS 失败返回清洗后的 502；容量/速率返回 503 和有限 Retry-After。上游 manifest 的 4xx/5xx 保留状态码但正文替换为固定 manifest 错误对象；动态 resource/redirect 的上游错误正文同样替换为固定动态错误对象。所有错误路径只透传经过 24 小时界限验证的单一 `Retry-After`，且失败请求不刷新 capability idle 时间。客户端响应、错误和日志不包含 target path/query、RequiredHeaders 或 capability。观察表只聚合规范化 authority、来源、决定、有限原因、时间和次数；协议拒绝进一步区分 request_unclassified、structured_body_limit、playback_info_denied、hls_feature_denied、dash_feature_denied、redirect_body_replay_denied，不保存 URL、query、DNS 回答、Header 或正文。2,048 项异步队列过载只增加 dropped 计数；记录保留 30 天且全库最多 10,000 行

### 边缘日志与 NAT 边界

- Meridian 自身的动态拒绝日志不记录目标路径/query；官方安装器生成的 Nginx access log 也不包含 query、Referer 或原始 request line，并把 `/_meridian/d/*` 记为 `/_meridian/d/[REDACTED]`。这些保证不覆盖第三方 CDN、负载均衡器、已有 Nginx 或其他边缘；capability 是 bearer，任何入口层都必须配置等价脱敏、最短必要保留期和访问控制
- 自目标防护只能看到操作系统接口地址以及配置的 `PANEL_DOMAIN`/站点 `public_host`。若一个公网 DNS/IP 通过 NAT、负载均衡或 hairpin 指回本机或内网，而公网别名没有分配在本机接口上，应用层可能仍把它视为公网。必须用出站/入口防火墙阻断这类公网别名、内网回流和不应访问的监听端口；不要把应用 SSRF 校验当成 NAT 或网络分段的替代品

### 部署与供应链

- Release 附带 `SHA256SUMS`，安装脚本在替换二进制前强制校验 SHA-256
- 发布工作流会先严格校验标签格式，再将校验后的值传给构建和镜像步骤
- 更新与改密流程在修改前创建权限为 `0600` 的内部备份，并在健康检查失败时自动恢复
- systemd 服务和官方 Docker 镜像默认以非 root 用户运行
- CI 执行竞态测试、`go vet`、`govulncheck`、`gosec` 与 CodeQL

## 支持的版本

当前项目处于活跃开发阶段，安全修复仅针对最新版本。
