# API 参考

本章给出 `mcp-kit` 暴露的主要 API 入口与定位（完整细节建议直接看 rustdoc）。

## mcp-kit

入口：`use mcp_kit::*;`

### 配置

- `Config::load(root, override_path)`：读取并校验 `mcp.json`（v1），并解析为 `Config`
- `Transport`：`Stdio | Unix | StreamableHttp`
- `ServerConfig`：按 transport 聚合后的 server 配置
  - `ServerConfig::streamable_http_split(sse_url, http_url)`：便捷构造 split URL 的 `transport=streamable_http`
- `StdoutLogConfig`：stdio server stdout 旋转日志配置
- `Root`：MCP roots 能力（`client.roots`）

### 连接与会话

- `Manager`：多 server 连接缓存 + initialize + 便捷请求
  - `from_config` / `new`
  - `connect` / `get_or_connect`
  - `request` / `notify` / `request_typed` / `notify_typed`
  - `list_tools` / `call_tool` / `read_resource` / `get_prompt` 等常用 MCP 方法
  - `connect_io` / `connect_jsonrpc`：接入自定义 transport
  - `with_server_request_handler` / `with_server_notification_handler`：处理 server→client
- `Session`：单连接 MCP 会话（已 initialize）
  - `request` / `notify`（raw）
  - `request_typed` / `notify_typed`
  - `list_tools` / `call_tool` / `read_resource` 等便捷方法

### typed 方法抽象（轻量）

- `McpRequest` / `McpNotification`：method + params/result 的轻量 trait（schema-agnostic）
- `mcp_kit::mcp`：常用方法的 typed wrapper 子集（`ListToolsRequest` / `CallToolRequest` / `ListResourcesRequest` …）

### 安全

- `TrustMode::{Untrusted, Trusted}`
- `UntrustedStreamableHttpPolicy`：Untrusted 下的远程出站策略（https/host/ip/allowlist/dns_check）

## mcp-jsonrpc

入口：`use mcp_jsonrpc::*;`

- `Client`：JSON-RPC 连接（stdio/unix/streamable_http/io）
  - `request(method, params)` / `notify(method, params)`
  - `take_requests()` / `take_notifications()`：消费 server→client 消息
- `ClientHandle`：可 clone 的写端句柄（用于 respond server→client requests）
- `IncomingRequest` / `Notification`
- `SpawnOptions` / `StdoutLog` / `Limits` / `StreamableHttpOptions`
- `Error` / `Id`

## 生成 rustdoc（推荐）

在 `mcp-kit/` 下：

```bash
cargo doc -p mcp-kit -p mcp-jsonrpc --no-deps
```
