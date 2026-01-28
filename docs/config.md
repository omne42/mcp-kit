# 配置

## 文件位置

默认（发现顺序，均相对 `--root`，默认当前工作目录）：

1. `./.mcp.json`
2. `./mcp.json`
3. `./.codepm_data/spec/mcp.json`（legacy）

可用 `mcpctl --config <path>` 覆盖（绝对或相对 `--root`）。

## schema（v1）

```json
{
  "version": 1,
  "client": {
    "protocol_version": "2025-06-18",
    "capabilities": {}
  },
  "servers": {
    "server_name": {
      "transport": "stdio",
      "argv": ["mcp-server-bin", "--stdio"],
      "env": { "KEY": "VALUE" },
      "stdout_log": {
        "path": "./.codepm_data/logs/mcp/server.stdout.log",
        "max_bytes_per_part": 1048576,
        "max_parts": 32
      }
    },
    "server_unix": {
      "transport": "unix",
      "unix_path": "/tmp/mcp.sock"
    },
    "remote": {
      "transport": "streamable_http",
      "url": "https://example.com/mcp",
      "http_headers": { "X-Client": "my-app" },
      "bearer_token_env_var": "MCP_TOKEN",
      "env_http_headers": { "X-Api-Key": "MCP_API_KEY" }
    }
  }
}
```

约束（fail-closed）：

- 顶层/servers.<name> 未知字段：拒绝（`deny_unknown_fields`）。
- `client.protocol_version`：可选；若存在必须非空字符串。
- `client.capabilities`：可选；若存在必须是 JSON object。
- `servers.<name>.argv`：当 `transport=stdio` 时必填；非空数组；每项必须非空字符串。
- `servers.<name>.unix_path`：当 `transport=unix` 时必填。
- `server_name`：只允许 `[a-zA-Z0-9_-]`。
- `transport`：v1 支持 `stdio` / `unix` / `streamable_http`。
- `servers.<name>.stdout_log`：仅 `transport=stdio` 支持；`path` 允许相对路径（相对 `--root`）。`max_bytes_per_part` 默认 1MiB（最小 1）。`max_parts` 默认 32（最小 1），`0` 表示不做保留上限（无限保留）。
- `transport=unix` 限制：不支持 `argv/env/stdout_log`（仅用于连接已有 unix socket server）。
- `transport=streamable_http`：需要 `servers.<name>.url`；不支持 `argv/unix_path/env/stdout_log`。
  - `bearer_token_env_var` / `env_http_headers` 会从本地环境变量读取 secrets；默认 `TrustMode::Untrusted` 下会拒绝读取，需要上层显式信任（见 `docs/design.md`）。
  - `http_headers` 是静态 header；默认 `TrustMode::Untrusted` 下会拒绝发送 `Authorization/Cookie/Proxy-Authorization`。
