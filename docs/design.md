# 设计

目标：把 “mcp.json 配置解析 + JSON-RPC（stdio / unix / streamable http）+ MCP 会话管理” 做成独立库/CLI，供上层产品复用。

## 核心数据结构

- `Config { client, servers: BTreeMap<String, ServerConfig> }`
- `Manager`：连接缓存 + MCP initialize + request/notify 便捷方法
- `Connection { child: Option<Child>, client }`（unix 连接没有 child）
- `McpRequest` / `McpNotification`：轻量 typed method 抽象（类似 `example/codex/codex-rs/mcp-types` 的 request/notification trait）
- `pm_mcp_kit::mcp`：常用 MCP method 的轻量 typed wrapper 子集（可选使用）
- `Session`：单连接 MCP 会话（已完成 initialize，可直接 request/notify 与调用便捷方法）
- `Manager::initialize_result`：暴露每个 server 的 initialize 响应（便于上层读取 serverInfo/capabilities 等信息）

## 边界

提供：

- `pm-jsonrpc`：最小 JSON-RPC client（stdio / unix / streamable http），支持 notifications 与可选 stdout 旋转落盘。
- `pm-mcp-kit`：`mcp.json` 解析、连接/初始化、请求超时与 server→client request/notification hook。
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

- 本仓库不引入 CodePM 的 thread/process 等领域 ID。
- 单连接写入会被串行化（避免并发写导致 JSON-RPC 输出交错）；允许并发发起请求，但会在写入层面排队。
- 需要处理 server→client 的 JSON-RPC request：`pm-mcp-kit::Manager` 默认对未知方法返回 `-32601 Method not found`，并提供可注入的 request/notification handler。

## 策略（v1）

- **日志**：由上层选择是否将 server stdout 旋转落盘（`pm-jsonrpc::SpawnOptions`，支持 `max_parts` 保留上限）。
- **超时**：`Manager` 级别的 per-request timeout（默认 30s）。
- **重连**：v1 不做自动重连；上层可通过 drop/重建连接实现。
- **并发**：同一连接串行；不同 server 可由上层并发使用多个 `Manager` 或拆分任务。
