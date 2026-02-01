# 日志与观测（stdout_log / stderr）

本章聚焦两件事：

- 如何抓到 stdio MCP server 的 stdout 交互（用于协议排查）
- 如何理解 `mcp-jsonrpc` 的 stdout 旋转日志行为（文件命名、保留策略）

## stdio 下的 stdout/stderr 约定

在 `transport=stdio` 场景里：

- **stdout**：通常承载 JSON-RPC 消息（MCP 协议数据）
- **stderr**：通常承载日志（人类可读的调试输出）

因此建议 MCP server 把日志写到 stderr，避免污染 stdout 的 JSON 流。

## stdout_log：抓取 server stdout（并旋转落盘）

`mcp-kit` 的配置字段：`servers.<name>.stdout_log`

启用后，`mcp-jsonrpc` 会把“从 server stdout 读到的每一行”（非全空白行）写入文件，便于：

- 复盘 MCP/JSON-RPC 往来消息
- 排查 server 输出了非 JSON 的内容（被 client 忽略）
- 排查消息顺序/分片/大小限制

示例：

```json
{
  "version": 1,
  "servers": {
    "local": {
      "transport": "stdio",
      "argv": ["mcp-server-bin", "--stdio"],
      "stdout_log": {
        "path": "./.mcp-kit/logs/mcp/server.stdout.log",
        "max_bytes_per_part": 1048576,
        "max_parts": 32
      }
    }
  }
}
```

约束：

- 仅 `transport=stdio` 支持
- `path` 可为相对路径（相对 `--root` 解析）
- `max_bytes_per_part` 最小为 `1`
- `max_parts=0` 在 `mcp-kit` 配置里表示“不限制保留数量”（无限保留）

> 注意：stdout_log 会把协议数据落盘，可能包含敏感信息。建议放到项目专用目录，并结合访问控制与清理策略使用。

## 旋转文件命名规则

假设 `path` 是：

`./.mcp-kit/logs/mcp/server.stdout.log`

当文件达到 `max_bytes_per_part` 后：

- 当前的 `server.stdout.log` 会被 rename 为：
  - `server.stdout.segment-0001.log`
  - `server.stdout.segment-0002.log`
  - ...
- 然后重新创建新的 `server.stdout.log` 继续写入

part 编号会从“已存在的最大编号 + 1”开始，避免覆盖历史文件。

## 保留策略：max_parts

- `max_parts = None`：保留所有 `*.segment-XXXX.log`
- `max_parts = Some(N)`：只保留最新的 N 个 segment 文件（更老的会被删除）

注意：`max_parts` 只约束 segment 文件数量；当前写入中的 base 文件（`server.stdout.log`）始终存在。

## 故障现象与建议

### server 把日志写到了 stdout

现象：

- stdout_log 中出现非 JSON 内容
- client 会忽略无法解析的 stdout 行（不影响后续 JSON 行），但可能让排查变困难

建议：

- 修改 server：把日志移到 stderr
- 或在 server 中加开关：`--log-to-stderr`

### stdout_log 写入失败

stdout_log 是 best-effort：

- 如果写入失败，`mcp-jsonrpc` 会打印一次错误并禁用后续 stdout_log（避免影响主链路）

建议：

- 确保 `path` 目录可创建/可写
- 避免把 log 路径指向不可写位置
