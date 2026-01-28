# mcpctl

`mcpctl` 是基于 `mcp.json` 的 MCP client/runner（config-driven; stdio/unix/streamable_http）。

默认安全策略：

- 默认不信任本地配置（`TrustMode::Untrusted`）
  - 拒绝 `transport=stdio|unix`
  - 允许 `transport=streamable_http`（默认仅 `https` 且非 localhost/私网）
- 需要完全信任时使用 `--trust`

## 常用示例

```bash
# 以当前目录为 root
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- list-servers

# 指定 root 与 config
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- --root /path/to/workspace --config ./.codepm_data/spec/mcp.json list-tools rg

# 远程 streamable_http server（默认无需 --trust）
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- list-tools remote

# 调用工具
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- call rg ripgrep.search --arguments-json '{"query":"foo"}'

# 发送 raw request（任意 MCP/JSON-RPC 方法）
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- request rg tools/list
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- request rg resources/read --params-json '{"uri":"file:///path/to/file"}'

# 发送 raw notification
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- notify rg notifications/initialized

# 完全信任（允许 stdio/unix + 允许读取 env secrets / 发送认证 header）
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- --trust list-tools rg

# 不完全信任，但放开部分 streamable_http 出站限制（仅影响远程）
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- --allow-host example.com list-tools remote
cargo run -p pm-mcp-kit --features cli --bin mcpctl -- --allow-private-ip --allow-http list-tools remote
```

`list-servers` 会回显解析后的 `client` 与每个 server 的 `stdout_log` 配置，便于确认最终生效配置。
