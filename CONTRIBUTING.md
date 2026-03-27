# 贡献指南

感谢你对 Meridian 的关注。本文档说明如何参与项目开发。

## 开发环境

- Go 1.23+
- 无 CGO 依赖（SQLite 使用纯 Go 实现 `modernc.org/sqlite`）

```bash
git clone https://github.com/snnabb/meridian.git
cd meridian
go build -o meridian .
go test ./...
```

## 项目架构约定

- **后端保持单文件**：所有后端逻辑写在 `main.go` 中，不拆分子包或多文件。这是项目的有意设计选择
- **前端是原生 JS**：不使用框架，不引入构建工具。页面按文件拆分在 `web/static/js/pages/` 下
- **SQLite 驱动名是 `sqlite`**（不是 `sqlite3`），不要更换驱动
- **嵌入方式**：前端通过 `web/embed.go` 的 `go:embed` 指令嵌入二进制

## 提交 PR 的流程

1. Fork 仓库
2. 从 `main` 分支创建你的特性分支
3. 修改代码
4. 确保 `go test ./...` 通过
5. 确保 `go build` 能正常编译
6. 提交 PR，使用 [PR 模板](.github/PULL_REQUEST_TEMPLATE.md) 填写说明

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

- 将 `main.go` 拆分成多文件的重构 PR
- 引入前端构建工具链（webpack、vite 等）
- 更换 SQLite 驱动
- 没有实际用途的"优化"或过度抽象
