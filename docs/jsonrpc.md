# pm-jsonrpc（JSON-RPC client）

`pm-jsonrpc` 是一个最小 JSON-RPC 2.0 client。它是 `pm-mcp-kit` 的底座，也可以独立使用。

## 核心类型

- `pm_jsonrpc::Client`：一个连接（可能包含 child process），提供 `request/notify` 并可接收 server→client 的 notifications/requests。
- `pm_jsonrpc::ClientHandle`：可 clone 的“写端 + pending map”，用于从 reader task 中回写响应。
- `pm_jsonrpc::Notification`：server→client notification（无 `id`）。
- `pm_jsonrpc::IncomingRequest`：server→client request（有 `id`，必须 respond）。

## 连接方式（transports）

- `Client::spawn(program, args)` / `spawn_with_options`：stdio spawn child
- `Client::connect_unix(path)`：连接已有 unix socket
- `Client::connect_streamable_http(url)` / `connect_streamable_http_with_options`：远程 HTTP SSE + POST
- `Client::connect_io(read, write)`：用任意 `AsyncRead/AsyncWrite` 作为 transport（测试/复用管道）

## Options：stdout log 与 DoS 防护

`SpawnOptions`：

- `stdout_log: Option<StdoutLog>`：把“读到的每一行”写到旋转日志（常用于 stdio server 的 stdout 协议排查）
- `limits: Limits`：限制单消息大小与队列容量（减少 DoS 风险）

`Limits`（默认值在代码中定义）：

- `max_message_bytes`：单条 JSON-RPC 消息（单行）的最大字节数
- `notifications_capacity`：缓存 server→client notifications 的队列长度
- `requests_capacity`：缓存 server→client requests 的队列长度

当 server→client requests 队列满时，`pm-jsonrpc` 会对该 request 立即回应 `-32000 client overloaded`（而不是无限堆积）。

## 安装 handler：处理 server→client

`pm-jsonrpc::Client` 默认会把 server→client 的消息放入 channel，调用方需要“取走并消费”：

```rust
let mut client = pm_jsonrpc::Client::connect_streamable_http("https://example.com/mcp").await?;

if let Some(mut requests) = client.take_requests() {
    tokio::spawn(async move {
        while let Some(req) = requests.recv().await {
            let _ = req.respond_ok(serde_json::json!({"ok": true})).await;
        }
    });
}
```

`pm-mcp-kit::Manager` 会在 install connection 时自动接管这部分（并提供可注入 handler），一般上层不需要直接操作 `pm-jsonrpc` 的 channel。

## Streamable HTTP 的安全/行为

`StreamableHttpOptions`：

- `headers`：额外 header
- `connect_timeout`：建立连接超时（默认 10s）
- `request_timeout`：POST 请求/响应 body 的超时（注意：不要用于限制 SSE 长连接）
- `follow_redirects`：是否跟随 HTTP redirects（默认 `false`，减少 SSRF 风险）

在 `pm-mcp-kit` 中：

- 会在 `Untrusted` 下对 URL/host/ip/header/env 做额外校验（见 [`安全模型`](security.md)）
- 会把 `Manager` 的 per-request timeout 传给 `StreamableHttpOptions.request_timeout`
