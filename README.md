# mcp-kit

独立的 MCP client/runner 基建目录（Rust workspace）。

包含：

- `pm-jsonrpc`：JSON-RPC（stdio / unix）client
- `pm-mcp-kit`：`mcp.json` 解析 + MCP（stdio）连接/生命周期管理
- `mcpctl`：基于配置的 MCP CLI（类似 “mcpctl”）

## 快速开始

```bash
# 在 mcp-kit/ 下
cargo run -p pm-mcp-kit --bin mcpctl -- --help
```

## 配置（v1 最小 schema）

默认读取：`./.codepm_data/spec/mcp.json`（相对 `--root`，默认当前目录）。

```json
{
  "version": 1,
  "servers": {
    "ripgrep": {
      "transport": "stdio",
      "argv": ["mcp-rg", "--stdio"],
      "env": { "NO_COLOR": "1" }
    }
  }
}
```

## 常用命令

```bash
mcpctl list-servers
mcpctl list-tools <server>
mcpctl call <server> <tool> --arguments-json '{"k":"v"}'
```

> 提示：默认不安装到 PATH，可用 `cargo run -p pm-mcp-kit --bin mcpctl -- ...`。

## 开发

- 启用 hooks：`git config core.hooksPath githooks`
- Rust gates：`cargo fmt --all && cargo check --workspace --all-targets && cargo test --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings`

