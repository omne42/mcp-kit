# streamable_http 传输详解（SSE + POST）

`transport=streamable_http` 是 `mcp-kit` 的远程优先方案：通过 **HTTP SSE** 接收 server 推送，通过 **HTTP POST** 发送 JSON-RPC request/notification。

本章描述的是 `mcp-jsonrpc` 的具体实现细节，便于你对接自建 server、排查联通性问题，或在安全评审时快速定位行为边界。

> 更高层（TrustMode/出站校验）见 [`安全模型`](security.md)。

## 一句话理解

- 建立一个 **GET SSE** 长连接：持续接收 JSON-RPC 消息（以及可能的 response stream）
- 每发起一次 JSON-RPC 请求：通过 **POST** 把 JSON 发给同一个 URL，然后把响应“桥接”为 JSON-RPC response

## URL 与请求方式

配置字段：`servers.<name>.url`

在 `mcp-jsonrpc` 中：

- SSE：`GET <url>`，并设置 `Accept: text/event-stream`
- POST：`POST <url>`，并设置 `Content-Type: application/json`

> 当前实现使用同一个 URL 同时承担 SSE 与 POST。

## 会话粘连：`mcp-session-id` header

如果 server 在响应头返回 `mcp-session-id`：

- client 会记录该值
- 后续每次 POST 都会携带 header：`mcp-session-id: <value>`
- 如果某次响应又返回新的 `mcp-session-id`，client 会更新并继续使用最新值

这使得 server 可以把多个 HTTP 请求关联到同一个会话。

## SSE 数据格式（client 期望）

`mcp-jsonrpc` 的 SSE pump 只关心 `data:` 字段：

- 会把同一个 event 中的多行 `data:` 拼接起来（用 `\n` 连接）
- 遇到空行表示一个 event 结束，此时把累计的 `data` 当作“一条 JSON-RPC 消息”，写入内部 JSON-RPC 读循环
- 如果累计 `data` 恰好是 `[DONE]`，则结束 SSE pump

简化示例：

```text
data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}

```

> `mcp-jsonrpc` 会把 `data:` 后面的内容原样写入 JSON-RPC 流（再由 JSON parser 解析）。

## POST 响应的两种形态

当 client POST 发送 JSON-RPC request 后，server 的响应可能是：

### 1）普通 JSON（最常见）

- response body 是 JSON（或至少是可被视为 JSON-RPC response 的 JSON 文本）
- client 会把 body 写回内部 JSON-RPC 读循环（等价于“收到一条 response”）

### 2）SSE（用于流式回包）

如果 `Content-Type` 以 `text/event-stream` 开头：

- client 会把这个 POST 的响应当作 SSE 流来 pump（同样按 `data:` 拼 event）
- pump 出来的 JSON-RPC 消息会被写回内部 JSON-RPC 读循环

## 超时与重试语义

`StreamableHttpOptions`：

- `connect_timeout`：只用于建立 SSE/HTTP 连接（默认 10s）
- `request_timeout`：用于单次 POST 的 send/response（包括 POST 返回 SSE 时的响应流）；不要用于限制主 SSE（GET）长连接

请求级别行为：

- 对 **request（有 id）**：HTTP 失败/超时会被桥接成 JSON-RPC error response（错误码 `-32000`），从而让 `request()` 返回错误
- 对 **notification（无 id）**：HTTP 失败无法回传 response，因此无法通过 JSON-RPC error 表达；上层通常只能把它当作“尽力而为的 fire-and-forget”

## Redirects 与代理

为了降低 SSRF 风险与行为不确定性：

- `follow_redirects` 默认 `false`（不跟随 30x）
- 默认禁用“自动读取系统代理环境变量”（`reqwest::Client::builder().no_proxy()`）

如果你需要不同的网络策略（例如走企业代理或允许 redirects），可以在上层自行构建 `mcp_jsonrpc::Client` 并接入 `mcp-kit`（见 [`作为库使用`](library.md) 的自定义 transport 章节）。

## 与 mcp-kit 的关系

`mcp-kit` 使用 `mcp-jsonrpc` 作为传输层，并在 `TrustMode::Untrusted` 下对 `streamable_http` 做额外校验：

- 只允许 `https://`（除非显式放开）
- 拒绝 localhost/私网 IP 字面量（除非显式放开）
- 拒绝敏感 header（Authorization/Cookie/Proxy-Authorization）
- 拒绝读取 env secrets（`bearer_token_env_var` / `env_http_headers`）

详见 [`安全模型`](security.md) 与 [`配置`](config.md)。
