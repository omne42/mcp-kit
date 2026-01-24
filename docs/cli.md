# mcpctl

`mcpctl` 是基于 `mcp.json` 的 MCP client/runner（stdio）。

## 常用示例

```bash
# 以当前目录为 root
cargo run -p pm-mcp-kit --bin mcpctl -- list-servers

# 指定 root 与 config
cargo run -p pm-mcp-kit --bin mcpctl -- --root /path/to/workspace --config ./.codepm_data/spec/mcp.json list-tools rg

# 调用工具
cargo run -p pm-mcp-kit --bin mcpctl -- call rg ripgrep.search --arguments-json '{"query":"foo"}'
```

