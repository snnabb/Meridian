# 更新与维护

“全局设置 → 版本更新”检查 GitHub 最新正式版本。更新方式取决于实际部署方式。

第一阶段开发版增加“恢复升级前版本和数据”，更新入口始终只提供正式版，无测试通道。旧 v1.14.2 更新代理仍可执行正式版更新；显式恢复快照需要新版代理及配套安装器。详见[第一阶段开发说明](phase1.md)。

## 升级到 v1.14.2

v1.14.2 包含泛域名 HTTPS 安装、Nginx 回源 SNI、同机反代真实 IP 和 Go 1.26.10 安全更新。v1.14.0 / v1.14.1 用户可按原部署方式升级，保留数据库、环境、密钥与证书；Docker 固定镜像使用 `ghcr.io/snnabb/meridian:v1.14.2`。

同机 Nginx / 宝塔覆盖设置 `X-Real-IP $remote_addr` 后，`TRUSTED_PROXY_CIDRS` 未设置或留空的安装只需升级程序，即会信任 `127.0.0.1` 和 `::1` 并记录真实 IP。已有自定义 CIDR 不会自动扩展，`none` 可关闭信任；跨容器的 1Panel / Docker 和远程代理仍须配置实际来源，见[手动反代与真实 IP](reverse-proxy.md#manual-proxy-client-ip)。

升级前备份程序、数据库、环境与服务配置。原生 HTTPS 的旧安装如尚未刷新更新组件，先按本文的旧组件修复步骤操作；无需为了升级重新申请证书或切换现有入口。

## 从 v1.14.0 升级到 v1.14.1

v1.14.1 将已验证的测试分支改进纳入正式版：网页与 Telegram 续期预设、自定义天数、账号状态筛选、续期历史、提醒处理与发送记录，以及仅显示日期的到期日。账号到期时间在数据库、API 和 JSON 中仍保留完整精度；显示变化不会重写已有时间。

标准 systemd 安装已配置更新代理时，可在面板检查新版本并升级。Docker 将固定镜像改为 `ghcr.io/snnabb/meridian:v1.14.1`，拉取后重建容器；使用 `latest` 时同样需要拉取并重建。继续使用原数据卷、环境配置和持久密钥。

启动时自动补齐续期与提醒记录所需数据表，已有站点、账号和提醒配置保留。更新前保存完整部署备份，更新后核对账号到期日、续期记录及 Telegram 设置。需要回退时，按[回滚说明](#rollback)同时恢复更新前的程序、数据库与配置。原生 HTTPS 的旧安装仍需先按下面的旧组件修复步骤刷新安装器。

## 从 v1.13.5 升级到 v1.14.0

已配置更新代理的标准 systemd 安装可直接在面板检查新版本并升级。账号功能所需数据表会在启动时自动创建，已有站点、管理员、线路和长期密钥保留。Docker 修改镜像为 `v1.14.0` 后拉取并重建，保留数据卷与密钥。

原生 HTTPS 部署若仍使用旧更新脚本，先按下面的旧组件修复步骤刷新一次安装器，再从网页升级。更新前保存完整部署备份；回退旧版本应同时恢复更新前数据库与配置。带预览后缀的本地构建可更新到更高数字版本的正式 Release。

## 更新方式

| 部署 | 更新方式 |
| --- | --- |
| 标准 Linux systemd 安装 | 面板内更新或一键安装器 `update`。 |
| Docker / Compose | 拉取镜像并重建容器，保持数据卷与密钥。 |
| Windows、macOS、手工或自定义目录 | 停止服务，替换对应平台程序后重新启动。 |

“检查新版本”可用，不代表当前部署支持面板内替换程序。

## 面板内更新

标准 Linux 安装器配置独立更新服务。面板向固定的本机更新代理发起任务，由更新服务执行受保护的安装流程。

1. 打开版本更新，检查最新正式版本与发布说明。
2. 导出 [加密备份](backup-and-restore.md)，确认环境配置与密钥已保存。
3. 确认更新，查看状态。
4. 等待服务重启与面板恢复，核对版本及站点功能。

下载执行 SHA-256 校验，有签名清单时验证 Sigstore；安装器创建备份、执行健康检查，失败时尝试回滚。

### v1.13.4 升级到 v1.13.5

已启用更新服务的标准 Linux 安装，使用 Nginx 提供 HTTPS、Meridian 内部提供 HTTP 时，可以直接在面板更新。

**原生 HTTPS 的旧安装需要先修复一次更新组件。** v1.13.4 随附安装器的健康检查固定使用 HTTP，会把正常运行的原生 HTTPS 判定为失败并触发回滚。面板显示“支持更新”只说明更新服务可连接，无法识别这个旧脚本问题。

先在服务器执行下面的命令。已有安装的 `install -y` 保留当前程序版本、域名、证书和数据，只补齐安装配置并更新组件；不要附加 `--domain`、`--port` 或 `--no-domain`：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/snnabb/Meridian/master/install.sh) install -y
```

完成后回到“全局设置 → 版本更新”，检查更新并点击“更新并重启”。修复后的安装器使用程序自带的本机健康检查，读取实际端口和数据库中的域名，并校验证书，兼容 HTTP 与原生 HTTPS。

这项修复于 v1.13.5 发布后同步到主分支安装器；已下载到服务器的旧更新脚本不会因 GitHub 发布新版而自动刷新。因此原生 HTTPS 用户不能省略首次组件修复，也不需要重装面板或重新申请证书。

新版安装器在首次安装、升级和检查到已是最新版时，都会配置或修复面板更新服务。旧标准安装没有更新代理时，在服务器运行一次：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/snnabb/Meridian/master/install.sh) update -y
```

这次操作会保留配置并补装更新服务，之后可直接在面板更新。仅修复更新组件时也可使用 `install -y`。自定义服务名、账户、目录和 Docker 不应强行启用标准更新代理。

## 安装器更新

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/snnabb/Meridian/master/install.sh) update
```

不要在同一部署上同时运行多个更新任务。更新时正在播放的连接可能中断，选择空闲时间执行。

## Docker 更新

固定版本部署先调整 `image` 标签，然后执行：

```bash
docker compose pull
docker compose up -d
docker compose ps
```

保留 `.env` 和数据卷，不使用 `down -v`。完整示例见 [Docker 部署](install-docker.md)。

## 手工更新

1. 备份数据、密钥和服务配置。
2. 停止运行中的 Meridian。
3. 下载与当前平台匹配的正式版本，校验文件。
4. 替换程序，保留原工作目录、数据库和环境。
5. 启动服务，检查版本、认证、站点和真实播放。

可以确认程序版本：

```bash
./meridian --version
```

## 回滚 {#rollback}

### 自动回滚范围

标准 Linux systemd 安装在替换程序前会停止服务，并同时创建两份更新前副本：

- `/opt/meridian-backups/meridian-pre-<version>-<timestamp>.tar.gz`：保留更新前的数据目录，供人工恢复。
- 更新临时目录中的整目录快照：用于本次事务失败时自动恢复。

快照是 `/opt/meridian` 的字节级副本，因此包括 `meridian.db`、SQLite 的 `-wal`、`-shm` 或 `-journal` 文件、`.env`、持久密钥以及数据目录中的其他文件。健康检查失败时，安装器会恢复旧二进制、整套数据快照和被安装器管理的 systemd 服务文件，然后重新启动原来的服务状态。

自动回滚只发生在这次更新事务仍在运行且新版本未通过健康检查时。快照恢复失败不会被当作成功，安装器会保留备份归档路径并提示手动恢复。

以下内容不在数据目录归档内，需要单独保存：`/etc/systemd/system/meridian.service`、安装器管理的 Nginx 配置、外部反向代理配置、证书路径指向的外部文件，以及 `DB_PATH` 指向 `/opt/meridian` 之外的数据库。

### 成功更新后的降级

第一阶段的新安装器在健康检查通过后保存 `/opt/meridian-backups/rollback-current/`，包含上一版程序、数据目录和服务文件。标准 systemd 部署可通过面板或 `sudo bash install.sh rollback` 一起恢复。仅支持数据库实际位于数据目录内且路径无符号链接的部署；不支持的数据库布局会在更新停服前报错。外部证书与 Nginx 配置不在快照内，Docker 不适用此一键回滚。

回滚会替换升级后新增的配置、账号及流量数据，操作前先保存当前数据归档。成功后已使用快照移入 `rollback-restored-*`，同一快照只能一键恢复一次；之后需从归档人工恢复，不提供多级撤销。失败时尝试恢复回滚前状态，应核对服务健康和日志。面板只有检测到完整快照才提供恢复按钮。

下面的人工方式适用于旧安装器、Docker 或没有配套快照的安装。

更新已经成功并退出后，安装器不会因为你随后替换旧二进制而自动恢复数据库。新版本可能已经完成数据库迁移，此时只替换程序可能导致旧程序无法读取新结构。应先恢复同一份更新前数据，再启动旧程序。

标准安装的手动恢复示例（执行前确认归档文件名）：

```bash
sudo systemctl stop meridian

# 先保留当前状态，便于再次取证或恢复
sudo mv /opt/meridian "/opt/meridian-after-update-$(date -u +%Y%m%dT%H%M%SZ)"

# 选择对应更新前归档，例如 meridian-pre-v1.13.2-*.tar.gz
ARCHIVE=/opt/meridian-backups/meridian-pre-v1.13.2-YYYYMMDDTHHMMSSZ-PID.tar.gz
sudo tar -tzf "$ARCHIVE" | grep -Fx 'meridian/' >/dev/null
sudo tar -xpf "$ARCHIVE" -C /opt

# 更新流程通常会留下上一版程序
sudo install -o root -g root -m 0755 \
  /usr/local/bin/meridian.previous /usr/local/bin/meridian
sudo systemctl daemon-reload
sudo systemctl start meridian
sudo systemctl status meridian --no-pager -l
```

如果 `DB_PATH` 是外部路径，必须在停止服务后另外恢复该数据库及其 `-wal`、`-shm`、`-journal` 文件；不要只恢复 `.db` 主文件。恢复后检查登录、站点入口、播放、Telegram、TLS 和流量数据。

跨结构版本降级时，恢复升级前对应版本的数据库与环境备份，再使用旧程序。不要仅替换二进制并继续使用新版本修改过的数据库。

## 忘记管理员密码

标准 Linux 部署使用：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/snnabb/Meridian/master/install.sh) password
```

其他部署先停止服务，再通过标准输入执行离线命令：

```bash
read -r -s -p '新密码: ' MERIDIAN_ADMIN_PASSWORD
printf '\n'
printf '%s\n' "$MERIDIAN_ADMIN_PASSWORD" | ./meridian admin reset-password \
  --db /data/meridian.db --password-stdin
unset MERIDIAN_ADMIN_PASSWORD
```

数据库必须已经存在且只有一个管理员。标准安装器同时轮换会话密钥，使旧登录失效；手工部署还应按实际环境管理会话密钥并重启服务。
