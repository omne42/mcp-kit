# 设计

目标：把 “mcp.json 配置解析 + JSON-RPC（stdio / unix / streamable http）+ MCP 会话管理” 做成独立库/CLI，供上层产品复用。

## 架构总览

从下到上分 3 层：

1. `mcp-jsonrpc`：负责“怎么把一条 JSON-RPC 消息送到对端，再把对端返回/推送的消息读回来”
2. `mcp-kit`：负责“按 MCP 约定 initialize，并把常用 MCP 方法封装成好用的 API”
3. `mcpctl`：基于配置的 CLI（把库能力暴露成命令行操作）

这套拆分的关键好处是：

- 上层可以仅依赖 `mcp-kit`（不需要 CLI）
- 上层也可以绕过配置，直接把自建 transport 注入 `Manager::connect_io/connect_jsonrpc`

## 核心数据结构

- `Config`：包含 `client` 与 `servers`（server name → `ServerConfig`）
- `Manager`：连接缓存 + MCP initialize + request/notify 便捷方法
- `Connection`：封装 child/client（stdio 有 child；unix/streamable_http 无），并提供 `wait*`/`client()`/`take_child()` 等接口
- `McpRequest` / `McpNotification`：轻量 typed method 抽象（参考 `docs/examples.md` 的用法示例）
- `mcp_kit::mcp`：常用 MCP method 的轻量 typed wrapper 子集（可选使用）
- `Session`：单连接 MCP 会话（已完成 initialize，可直接 request/notify 与调用便捷方法）
- `Manager::initialize_result`：暴露每个 server 的 initialize 响应（便于上层读取 serverInfo/capabilities 等信息）

## 初始化流程（简化）

以 `Manager::request(...)` 为例：

1. 若未连接：根据 `ServerConfig::transport()` 建立 JSON-RPC 连接（stdio/unix/streamable_http）
2. 调用 MCP `initialize`，并缓存 initialize result
3. 发送 `notifications/initialized`
4. 发送用户请求（例如 `tools/list`）

## server→client（反向消息）

MCP/JSON-RPC 允许 server 主动发消息给 client：

- notification：只需要消费
- request：需要 client respond

`mcp-jsonrpc` 会把它们放进有界 channel。

`mcp_kit::Manager` 会在安装连接时：

- `take_requests()`：起一个任务循环消费 server→client requests，并交给 `server_request_handler`
- `take_notifications()`：起一个任务循环消费 server→client notifications，并交给 `server_notification_handler`

默认 handler：

- request：未知方法返回 `-32601 Method not found`
- 若启用 roots：内建响应 `roots/list`

## 并发与背压

- 同一连接：写入串行化（避免 JSON-RPC 输出交错）；可以并发发起请求，但写入层会排队
- server→client：有界队列；requests 队列满会立刻回复 `-32000 client overloaded`（保护客户端内存）

## 边界

提供：

- `mcp-jsonrpc`：最小 JSON-RPC client（stdio / unix / streamable http），支持 notifications 与可选 stdout 旋转落盘。
- `mcp-kit`：`mcp.json` 解析、连接/初始化、请求超时与 server→client request/notification hook。
  - 安全默认：`Manager` 默认 `TrustMode::Untrusted`。
    - 拒绝 `transport=stdio|unix`（避免不可信仓库导致本地执行/本地 socket 滥用）
    - `transport=streamable_http` 仅允许 `https` 且非 localhost/私网目标；并拒绝发送 `Authorization`/`Cookie` 等敏感 header、拒绝读取 env secrets 用于认证 header
    - 仅在上层显式设置 `TrustMode::Trusted` 后才放开
    - 上层也可通过 `Manager::with_untrusted_streamable_http_policy(UntrustedStreamableHttpPolicy)` 自定义 untrusted 下的出站策略（allowlist / 允许 http / 允许私网等）
  - 若配置了 `client.roots`（或通过 `Manager::with_roots`），会自动声明 `capabilities.roots` 并内建响应 server→client 的 `roots/list`。
  - 除 stdio/unix 外，也可通过 `Manager::connect_io` / `Manager::connect_jsonrpc` 接入自定义 JSON-RPC transport（例如测试或自建管道）。
  - 也可用 `Manager::{get_or_connect_session, connect_*_session}` 在握手完成后取出 `Session`，将“单 server 会话”交给其他库持有。
  - 便捷方法覆盖 MCP 常用请求：`ping` / `tools/*` / `resources/*` / `prompts/*` / `logging/setLevel` / `completion/complete`；其他方法可用 `Manager::request` / `Manager::request_typed`。

不提供：

- MCP server 实现（仅 client/runner）。
- 高层语义（如 approvals、sandbox、工具执行策略等），由上层决定。
- 自动重连/守护进程（需要时由上层 drop/重建连接）。

约束：

- 本仓库不引入任何上层应用的 thread/process 等领域 ID。
- 单连接写入会被串行化（避免并发写导致 JSON-RPC 输出交错）；允许并发发起请求，但会在写入层面排队。
- 需要处理 server→client 的 JSON-RPC request：`mcp_kit::Manager` 默认对未知方法返回 `-32601 Method not found`，并提供可注入的 request/notification handler。

## 策略（v1）

- **日志**：由上层选择是否将 server stdout 旋转落盘（`mcp_jsonrpc::SpawnOptions`，支持 `max_parts` 保留上限）。
- **超时**：`Manager` 级别的 per-request timeout（默认 30s）。
- **重连**：v1 不做自动重连；上层可通过 drop/重建连接实现。
- **并发**：同一连接串行；不同 server 可由上层并发使用多个 `Manager` 或拆分任务。
