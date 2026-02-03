# Changelog

本项目的所有重要变更都会记录在这个文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- `mcp-jsonrpc`：最小 JSON-RPC client（stdio / unix / streamable http），支持 notifications 与可选 stdout 旋转落盘。
- `mcp-jsonrpc`：新增 `ClientStats` / `Client::stats()` / `ClientHandle::stats()`，统计无效 JSON 行与因队列满/关闭导致的 notifications 丢弃数量。
- `mcp-jsonrpc`：新增 `Client::connect_streamable_http_split_with_options(sse_url, http_url, ...)`，支持分离的 SSE 与 POST URL。
- `mcp-kit`：`mcp.json`（v1）解析、MCP server 连接与连接缓存管理（`Config/Manager/Connection`）。
- `mcpctl`：基于配置的 MCP CLI（list-servers/list-tools/list-resources/list-prompts/call）。
- `mcpctl`：新增 `--dns-check`，可选启用 Untrusted 下的 hostname DNS 校验。
- `McpRequest` / `McpNotification`：轻量 typed method trait + `Manager::{request_typed, notify_typed}`。
- `mcp_kit::mcp`：常用 MCP methods 的轻量 typed wrapper 子集（参考 `docs/examples.md`）。
- `transport=streamable_http`：原生支持远程 MCP server（HTTP SSE + POST），配置字段 `servers.<name>.url`。
- `transport=streamable_http`：支持分离配置 `servers.<name>.sse_url` + `servers.<name>.http_url`。
- `TrustMode`：安全默认不信任本地配置；需要显式切换到 Trusted 才允许从配置启动/连接 server。
- `roots/list`：当配置了 `client.roots` 时，内建响应 server→client request，并自动声明 `capabilities.roots`。
- `Manager::{connect_io, connect_jsonrpc}`：支持接入自定义 JSON-RPC 连接（便于测试与复用 transport）。
- `Manager::initialize_result`：暴露 server initialize 响应。
- `Manager`：补齐 MCP 常用请求便捷方法（`ping`、`resources/templates/list`、`resources/read`、`resources/subscribe`、`resources/unsubscribe`、`prompts/get`、`logging/setLevel`、`completion/complete`）。
- `Session`：单连接 MCP 会话（从 `Manager` 取出后可独立调用 `request/notify` 与便捷方法）。
- `Manager::{take_session, get_or_connect_session, connect_*_session}`：支持把握手完成的会话交给上层库持有。
- `mcp-kit`：`Config::load` 支持 Cursor/Claude Code 常见的 `.mcp.json` / `mcpServers` 兼容格式（best-effort）。
- `mcp-jsonrpc`：`streamable_http` 兼容握手前 `GET SSE` 返回 `405`，并在 `202 Accepted`（或首次获得 `mcp-session-id`）后自动重试建立 inbound SSE。
- Examples: add runnable `client_with_policy`, `in_memory_duplex`, and `streamable_http_split` under `crates/mcp-kit/examples/`.
- Docs: expand runnable examples section and clarify Untrusted/Trusted usage in `docs/examples.md`.

### Changed
- `Config::load` 默认路径发现：`./.mcp.json` / `./mcp.json`。
- `mcpctl` 现在需要 `--features cli` 构建（避免 library 依赖方被迫引入 clap）。
- `mcp_kit::Manager` 默认 `TrustMode::Untrusted`：拒绝 `transport=stdio|unix`；`streamable_http` 仅允许 `https` 且非 localhost/私网目标，并拒绝发送敏感 header/读取 env secrets 用于认证；需显式 `with_trust_mode(TrustMode::Trusted)` 覆盖。
- `mcp_kit::Manager` 支持自定义 untrusted 下的 `streamable_http` 出站策略：`with_untrusted_streamable_http_policy(UntrustedStreamableHttpPolicy)`。
- `mcpctl` 默认不信任本地配置：本地 stdio/unix 或需要读取 env secrets 的远程 server 需要 `--trust`。
- `mcp-jsonrpc` 增加 DoS 防护：限制单条消息大小并使用有界队列缓存 server→client 的 requests/notifications。
- `mcp-jsonrpc`：无参 requests/notifications 不再发送 `"params": null`（会省略 `params`）；新增 `Client::request_optional`。
- `mcp-jsonrpc`：server→client request 的 `id` 非法时会返回 `-32600 Invalid Request`（`id=null`），不再静默丢弃。
- `mcp-jsonrpc`（BREAKING）：`ClientHandle::respond_error_raw_id` 改为 crate 内部 API（`pub(crate)`），不再对外暴露。
- `mcp-jsonrpc`：`streamable_http` 的 SSE connect 会校验 `Content-Type: text/event-stream`（大小写不敏感）；POST 成功响应会校验 JSON `Content-Type` 与 JSON body，避免 pending 悬挂；HTTP 响应过大时会对对应 request 返回 error。
- `mcp-jsonrpc`：`streamable_http` 的 POST 会发送 `Accept: application/json, text/event-stream`；GET SSE 断开/失败会关闭 client 并 fail fast（避免静默丢失推送）。
- `mcp-jsonrpc`：`[DONE]` 只用于结束 POST 返回 SSE 的响应流；主 SSE（GET）不会把 `[DONE]` 当作断开信号。
- `mcp-jsonrpc`（BREAKING）：server→client 的 `Notification/IncomingRequest` 现在用 `Option<serde_json::Value>` 表达 `params`（保留 “省略 vs null” 语义）。
- `mcp-kit`：`transport=unix|streamable_http` 现在只要配置里出现 `argv` 字段（即使为空数组）也会被拒绝。
- `mcp-kit`：当 transport 发生 I/O/协议层错误时会自动清理连接缓存（下次请求会重新连接）。
- `mcp-kit`（BREAKING）：`ServerConfig` 新增 `sse_url/http_url` 字段以支持 streamable_http 分离 URL。
- `mcp-kit`（BREAKING）：`UntrustedStreamableHttpPolicy` 新增 `dns_check` 字段（默认关闭），用于可选启用 hostname DNS 校验。
- `mcp_kit::mcp`（BREAKING）：无参请求/通知的 `Params` 改为 `()`；部分 list 请求的 `Params` 由 `Option<...>` 改为必填结构体；`Result` type alias 弃用，改用 `JsonValue`（或 `serde_json::Value`）。
- `mcp_kit::mcp`（BREAKING）：`ToolInputSchema/ToolOutputSchema` 现在会保留未知 JSON Schema 字段（`flatten` 到 `extra`）。
- `mcp-kit`：`Session/Manager` 的无参请求不再产生 `"params": null`；typed request 的 (de)serialize 错误包含 method/server；`initialize` 会检测 `protocolVersion` mismatch。
- `mcp-kit`（BREAKING）：server→client 的 `ServerRequestContext/ServerNotificationContext` 现在用 `Option<serde_json::Value>` 表达 `params`（保留 “省略 vs null” 语义）。
- `mcp-jsonrpc` 的 `streamable_http` 增加超时能力：默认 connect timeout=10s；可选 per-request timeout（`mcp-kit` 会用 `Manager` 的 per-request timeout 进行设置）。
- `mcp-jsonrpc` 的 `streamable_http` 默认不跟随 HTTP redirects（减少 SSRF 风险），可通过 `StreamableHttpOptions.follow_redirects` 显式开启。
- `mcp-jsonrpc` 的 stdout 旋转日志支持保留上限：`StdoutLog.max_parts`（`mcp-kit` 配置字段 `servers.<name>.stdout_log.max_parts`）。
- Docs: add runnable example `crates/mcp-kit/examples/minimal_client.rs` and reference it from `docs/examples.md`.
- Docs: clarify `StreamableHttpOptions.request_timeout` semantics in `docs/jsonrpc.md`.
- Docs: document split `sse_url/http_url`, `--dns-check`, and updated `[DONE]` semantics for streamable_http.
- Docs: expand GitBook-style documentation under `docs/` and add `CONTRIBUTING.md`.
- `mcp-kit`：`mcp.json v1` 中 `http_headers` 现在也接受别名字段 `headers`（便于复用 Cursor 等配置片段）。

### Fixed
- `mcp-jsonrpc`：当 server→client request 的 `jsonrpc` 版本非法但 `id` 合法时，`-32600 Invalid Request` 现在会回显原始 `id`（而不是 `null`），保持 JSON-RPC 2.0 相关性语义。
- `mcp-jsonrpc`：补齐 `streamable_http` 的回归覆盖（`mcp-session-id` 复用/更新、POST 返回 SSE + `[DONE]`、非 JSON `Content-Type` 的错误桥接）。
- `mcp-jsonrpc`：当入站消息包含 `method` 但类型非法时，会返回 `-32600 Invalid Request`（若有 `id`）并避免误当作 response 消费 pending。
- `mcp-jsonrpc`：`streamable_http` 的 HTTP 200 + 空 JSON body（非 202）现在会桥接为 `-32000` error，避免 request 悬挂。
- `mcp-kit`：对无 child 的连接（unix/streamable_http）会检查 JSON-RPC client closed 状态并清理缓存，避免复用失活连接。
- `mcp-kit`：Cursor/Claude style 外部配置中 `type=http|sse` 与推断 transport 冲突时会 fail-closed 报错。
