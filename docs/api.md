# API 参考

本章给出 `mcp-kit` 暴露的主要 API 入口与定位（完整细节建议直接看 rustdoc）。

## mcp-kit

入口：`use mcp_kit::*;`

### 配置

- `Config::load(root, override_path)`：读取并校验 `mcp.json`（v1），并解析为 `Config`
- `Config::load_required(root, override_path)`：读取并校验 `mcp.json`；若未找到配置文件会报错（fail-fast），不会返回“空配置”
- `Transport`：`Stdio | Unix | StreamableHttp`
- `ServerConfig`：按 transport 聚合后的 server 配置
  - `ServerConfig::streamable_http_split(sse_url, http_url)`：便捷构造 split URL 的 `transport=streamable_http`（返回 `Result`）
  - `inherit_env`：仅 `transport=stdio` 生效；是否继承宿主环境变量（默认 `false`）
- `StdoutLogConfig`：stdio server stdout 旋转日志配置
- `Root`：MCP roots 能力（`client.roots`）

### 连接与会话

- `ServerName`：server 名称的新类型（用于 `Config` 的 `servers` key、`Manager` 的连接缓存 key、以及 `ProtocolVersionMismatch.server_name` 等）。大多数 API 仍接受 `&str` 查询；只有在你手动构造/持有会话（例如 `Session::new`）时需要显式构造 `ServerName`。注意：`ServerName::parse(...)` 会对输入做 `trim()` 后再校验，因此 `" a "` 与 `"a"` 会归一化为同一个名称；若你已经持有 `ServerName`，可优先使用 `Config::server_named`、`Manager::*_named` 这类入口避免重复处理/减少传参噪音。
- `Manager`：多 server 连接缓存 + initialize + 便捷请求
  - `from_config` / `new`
  - `connect` / `get_or_connect`
  - `request` / `notify` / `request_typed` / `notify_typed`
  - `list_tools` / `call_tool` / `read_resource` / `get_prompt` 等常用 MCP 方法
  - 注意：`is_connected/connected_server_names` 与 `*_connected` 系列方法需要 `&mut self`（会做连接存活性检查，并在 I/O/协议错误时自动清理坏连接）
  - `connect_io` / `connect_jsonrpc`：接入自定义 transport
  - `with_server_request_handler` / `with_server_notification_handler`：处理 server→client
  - `with_server_handler_concurrency` / `with_server_handler_timeout`：限制 server→client handler 的并发与超时（超时会计数，便于排查 silent drop）
  - `server_handler_timeout_count(srv)` / `server_handler_timeout_counts()`：读取 server→client handler 超时计数
  - `ProtocolVersionCheck` / `with_protocol_version_check`：控制 `initialize.protocolVersion` mismatch 的处理策略
  - `protocol_version_mismatches()` / `take_protocol_version_mismatches()`：读取/取走协议版本 mismatch 告警
- `Session`：单连接 MCP 会话（已 initialize）
  - `request` / `notify`（raw）
  - `request_typed` / `notify_typed`
  - `list_tools` / `call_tool` / `read_resource` 等便捷方法

### typed 方法抽象（轻量）

- `McpRequest` / `McpNotification`：method + params/result 的轻量 trait（schema-agnostic）
- `mcp_kit::mcp`：常用方法的 typed wrapper 子集（`ListToolsRequest` / `CallToolRequest` / `ListResourcesRequest` …）

### 安全

- `TrustMode::{Untrusted, Trusted}`
- `UntrustedStreamableHttpPolicy`：Untrusted 下的远程出站策略（https/host/ip/allowlist/dns_check/timeout/fail-open）

## mcp-jsonrpc

入口：`use mcp_jsonrpc::*;`

- `Client`：JSON-RPC 连接（stdio/unix/streamable_http/io）
  - `request(method, params)` / `notify(method, params)`
  - `wait()`：等待 child 退出；对无 child 的连接返回 `Ok(None)`
  - `wait_with_timeout(timeout, on_timeout)`：等待 child 退出（带超时）
  - `take_requests()` / `take_notifications()`：消费 server→client 消息
- `ClientHandle`：可 clone 的写端句柄（用于 respond server→client requests）
- `WaitOnTimeout`：`Client::wait_with_timeout` 的超时策略
- `IncomingRequest` / `Notification`
- `SpawnOptions` / `StdoutLog` / `Limits` / `StreamableHttpOptions`
- `Error` / `Id`

## 生成 rustdoc（推荐）

在 `mcp-kit/` 下：

```bash
cargo doc -p mcp-kit -p mcp-jsonrpc --no-deps
```
