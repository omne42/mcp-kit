# 发布与版本

本项目遵循：

- 版本号：Semantic Versioning
- 变更记录：Keep a Changelog（见 `CHANGELOG.md`）

## workspace 版本

`mcp-kit` 是 workspace，版本号在 `mcp-kit/Cargo.toml` 的：

- `[workspace.package] version`

## 发布检查清单（建议）

1. 更新 `CHANGELOG.md`：把本次变更整理到对应版本
2. bump 版本号：更新 `mcp-kit/Cargo.toml`（必要时更新 `Cargo.lock`）
3. 跑一遍 gates（见 [`贡献指南`](contributing.md)）
4. 打 tag（例如 `vX.Y.Z`）

> 若未来需要发布到 crates.io，建议把 `mcp-jsonrpc` / `mcp-kit` 分别 publish，并确保 README/docs 与 feature flags 描述一致。
