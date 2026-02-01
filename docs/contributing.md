# 贡献指南

欢迎贡献！本项目目标是成为“可复用的 MCP client/runner 基建”，因此对**安全默认值**与**向后兼容**较为敏感。

## 开发环境

- Rust `1.85+`
- 建议启用本仓库自带 hooks：

```bash
cd mcp-kit
git config core.hooksPath githooks
```

## 本地验证（gates）

```bash
cargo fmt --all
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## 提交内容的基本要求

- 变更 `mcp.json` schema：请同时更新 `docs/config.md` 与相关测试。
- 变更 TrustMode/策略：请更新 `docs/security.md`，并尽量补测试覆盖。
- 新增常用 MCP 方法：优先在 `mcp_kit::mcp` 添加 typed wrapper，并在 `docs/library.md` / `docs/api.md` 里补入口说明。
- 影响 CLI：更新 `docs/cli.md`，并保证 `--help` 与文档一致。

## PR 建议

- 一次 PR 聚焦一个主题（配置/安全/transport/CLI 等）
- 尽量提供复现步骤或最小示例
- 如果会影响用户行为，请在 `CHANGELOG.md` 的 `[Unreleased]` 下补条目
