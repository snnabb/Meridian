# 贡献指南

感谢你对 Meridian 的关注。本文档说明如何参与项目开发。

## 开发环境

- Go 1.26.10 或更高版本
- Node.js 22+
- 无 CGO 依赖（SQLite 使用纯 Go 实现 `modernc.org/sqlite`）

```bash
git clone https://github.com/snnabb/Meridian.git
cd Meridian
go build -o meridian ./cmd/meridian
go test ./...
node --test tests/*.test.js
```

## 项目架构约定

- **后端保持轻量**：可执行程序位于 `cmd/meridian/`，独立模块按现有职责文件组织，不引入不必要的包层级
- **前端是原生 JS**：不使用框架，不引入构建工具。页面按文件拆分在 `web/static/js/pages/` 下
- **SQLite 驱动名是 `sqlite`**（不是 `sqlite3`），不要更换驱动
- **嵌入方式**：前端通过 `web/embed.go` 的 `go:embed` 指令嵌入二进制

## 提交 PR 的流程

1. Fork 仓库
2. 从 `master` 分支创建你的特性分支；存在活动的 `beta` 测试分支时，针对该轮整合的问题也可基于 `beta` 提交
3. 修改代码
4. 确保 `go test ./...`、`go vet ./...` 和 `node --test tests/*.test.js` 通过
5. 确保 `go build -trimpath -buildvcs=false -o meridian ./cmd/meridian` 能正常编译
6. 提交 PR，使用 [PR 模板](.github/PULL_REQUEST_TEMPLATE.md) 填写说明

## 测试版分支

`beta` 按需从 `master` 创建，用于集中验证待发布改动，保留被整合 PR 的提交历史；整合完成并正式发布后可清理，下一轮再从最新主支创建。推送与目标为 `beta` 的 PR 都运行 CI 和 CodeQL；`beta` 推送还附带带提交号的 Linux x86-64 测试程序。Wiki 在该分支只构建和检查，正式文档站由 `master` 发布。安装器和面板更新默认使用正式 Release；主动选择测试通道后可安装已签名的 `vX.Y.Z-beta.N` Release。分支测试程序不会自动进入更新通道，下载见 [源码与测试版](docs/wiki/install-source.md)。

## 版本发布后的同步验证

每次推送并发布新版本后，还需完成文档与演示站同步，不能仅以 Release 上传成功作为结束：

1. 更新 `CHANGELOG.md`、README 版本信息，以及受影响的部署、使用和 Wiki 文档；检查文档站发布结果。
2. 先在测试环境验证，再在正式部署环境验证；操作前备份，保留原站点、账号、密钥、证书和回滚方式。
3. 同步公开演示站主入口与 `/test/` 的程序和版本说明，保持虚构数据、只读限制及禁止消息发送。
4. 验证演示站两个入口的登录、页面和 API，核对实际运行版本与页面说明一致。

服务器地址与登录凭据通过私有运维记录管理，不写入仓库或公开文档。草稿分支提交不等同于正式版本发布。

## 提交规范

Commit message 应简明扼要地说明改了什么：

- `fix: 修复站点启停时的流量 flush 问题`
- `feat: 添加播放地址分流配置`
- `docs: 更新诊断功能说明`

## 代码风格

- Go 代码遵循 `gofmt` 格式化
- 前端 JS 无特殊 lint 要求，保持现有风格一致即可
- 不要引入新的外部依赖，除非有充分理由

## 什么样的贡献是受欢迎的

- Bug 修复
- 测试覆盖率提升
- 文档改进
- Roadmap 中列出的功能实现（多用户、审计日志、通知集成）

## 什么样的改动会被拒绝

- 仅为形式统一而进行、没有构建或维护收益的包拆分
- 引入前端构建工具链（webpack、vite 等）
- 更换 SQLite 驱动
- 没有实际用途的"优化"或过度抽象
