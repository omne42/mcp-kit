# 配置

## 文件位置

默认（写死）：`./.codepm_data/spec/mcp.json`（相对 `--root`，默认当前工作目录）。

可用 `mcpctl --config <path>` 覆盖（绝对或相对 `--root`）。

## schema（v1）

```json
{
  "version": 1,
  "servers": {
    "server_name": {
      "transport": "stdio",
      "argv": ["mcp-server-bin", "--stdio"],
      "env": { "KEY": "VALUE" }
    }
  }
}
```

约束（fail-closed）：

- 顶层/servers.<name> 未知字段：拒绝（`deny_unknown_fields`）。
- `servers.<name>.argv`：非空数组；每项必须非空字符串。
- `server_name`：只允许 `[a-zA-Z0-9_-]`。
- `transport`：v1 只支持 `stdio`。

