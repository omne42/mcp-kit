# 调优与限制（timeouts / limits / 并发）

本章整理 `mcp-kit` 的几个关键“旋钮”，用于在不同场景下做可靠性/性能/安全权衡。

## 超时（timeout）

### `mcp_kit::Manager` / `Session`：per-request timeout

- `Manager` 默认 timeout：30s
- `mcpctl` 默认 `--timeout-ms 30000`

这会影响：

- `Manager::request/*` / `Session::request/*`：等待 JSON-RPC response 的最长时间
- `transport=streamable_http` 下：POST 请求的超时（`mcp_jsonrpc::StreamableHttpOptions.request_timeout`）

建议：

- 慢 server 或网络不稳定：增大 timeout
- 明确需要快速失败：减小 timeout，并在上层做重试/降级

### streamable_http：connect_timeout

`mcp-jsonrpc` 的 streamable_http 默认 connect timeout 为 10s（用于建立 HTTP 连接/发起 SSE GET）。

如果你需要修改 connect_timeout，需要在上层自行构建 `mcp_jsonrpc::Client::connect_streamable_http_with_options(...)` 并接入 `mcp-kit`（见下文“自定义 Limits/Options”）。

## DoS 防护与队列（mcp_jsonrpc::Limits）

`mcp-jsonrpc` 内置了几类限制，默认值适用于大多数 MCP server，但你可以按需调整。

### 1）单条消息大小：`max_message_bytes`

限制的是“一行 JSON-RPC 消息”的最大字节数（stdio/unix）以及 SSE event 的最大累计 `data` 字节数（streamable_http）。

过大风险：

- 内存占用与解析开销上升

过小风险：

- 大返回值（例如 `resources/read` 大文件/大 JSON）会触发错误

### 2）server→client 通知队列：`notifications_capacity`

server→client notifications 会进入有界队列：

- 队列满时，新的 notification 会被丢弃（best-effort）

如果你的 server 会大量推 notification（例如日志/进度），可以调大。

### 3）server→client requests 队列：`requests_capacity`

server→client requests（需要 respond）同样进入有界队列：

- 队列满时，`mcp-jsonrpc` 会对该 request 立即回复 JSON-RPC error：`-32000 client overloaded`

如果你的 server 会频繁发起 server→client request（例如 roots/list / 其他反向调用），建议调大或确保 handler 足够快。

## 并发模型（重要）

### 同一连接的写入串行化

为了避免 JSON-RPC 输出交错，同一连接的写入被串行化：

- 你可以并发发起多个 request（上层 future 并发）
- 但底层写入会排队，并按顺序写入

### 不同 server 并发

不同 server 之间互不影响：

- 同一个 `Manager` 可以同时管理多个连接
- 也可以在上层用多个 `Manager` 做隔离（按需）

## 自定义 Limits/Options（高级）

`mcp-kit` 默认使用 `mcp_jsonrpc::SpawnOptions::default()`（即默认 Limits）。

如果你需要自定义 Limits（或 streamable_http 的 connect_timeout / follow_redirects 等），推荐路径是：

1. 直接用 `mcp-jsonrpc` 构建 client（带 options）
2. 用 `Manager::connect_jsonrpc(...)` 或 `connect_jsonrpc_session(...)` 接入

示例（调大 server→client requests 队列）：

```rust
use mcp_jsonrpc::{Client, Limits, SpawnOptions};

let mut client = Client::connect_streamable_http_with_options(
    "https://example.com/mcp",
    Default::default(),
    SpawnOptions {
        limits: Limits {
            requests_capacity: 256,
            ..Default::default()
        },
        ..Default::default()
    },
)
.await?;

manager.connect_jsonrpc("remote", client).await?;
```

> 这条路径同样适用于 `connect_io_with_options`（例如测试时使用 `tokio::io::duplex`）。

可运行版本见：`crates/mcp-kit/examples/streamable_http_custom_options.rs`。

## 常见调优建议

- 远程网络慢：增大 `--timeout-ms`（或 `Manager::with_timeout`）
- server 会推大量反向 request：调大 `requests_capacity`
- 返回体很大：调大 `max_message_bytes`（并评估内存风险）
- 安全优先：尽量保持默认 Untrusted，并使用 `--allow-host` 收敛远程出站范围
