# Changelog

本项目的所有重要变更都会记录在这个文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- `mcp-jsonrpc`：最小 JSON-RPC client（stdio / unix / streamable http），支持 notifications 与可选 stdout 旋转落盘。
- `mcp-kit`：`mcp.json`（v1）解析、MCP server 连接与连接缓存管理（`Config/Manager/Connection`）。
- `mcpctl`：基于配置的 MCP CLI（list-servers/list-tools/list-resources/list-prompts/call）。
- `McpRequest` / `McpNotification`：轻量 typed method trait + `Manager::{request_typed, notify_typed}`。
- `mcp_kit::mcp`：常用 MCP methods 的轻量 typed wrapper 子集（参考 `example/codex/codex-rs/mcp-types`）。
- `transport=streamable_http`：原生支持远程 MCP server（HTTP SSE + POST），配置字段 `servers.<name>.url`。
- `TrustMode`：安全默认不信任本地配置；需要显式切换到 Trusted 才允许从配置启动/连接 server。
- `roots/list`：当配置了 `client.roots` 时，内建响应 server→client request，并自动声明 `capabilities.roots`。
- `Manager::{connect_io, connect_jsonrpc}`：支持接入自定义 JSON-RPC 连接（便于测试与复用 transport）。
- `Manager::initialize_result`：暴露 server initialize 响应。
- `Manager`：补齐 MCP 常用请求便捷方法（`ping`、`resources/templates/list`、`resources/read`、`resources/subscribe`、`resources/unsubscribe`、`prompts/get`、`logging/setLevel`、`completion/complete`）。
- `Session`：单连接 MCP 会话（从 `Manager` 取出后可独立调用 `request/notify` 与便捷方法）。
- `Manager::{take_session, get_or_connect_session, connect_*_session}`：支持把握手完成的会话交给上层库持有。

### Changed
- `Config::load` 默认路径发现：`./.mcp.json` / `./mcp.json`。
- `mcpctl` 现在需要 `--features cli` 构建（避免 library 依赖方被迫引入 clap）。
- `mcp_kit::Manager` 默认 `TrustMode::Untrusted`：拒绝 `transport=stdio|unix`；`streamable_http` 仅允许 `https` 且非 localhost/私网目标，并拒绝发送敏感 header/读取 env secrets 用于认证；需显式 `with_trust_mode(TrustMode::Trusted)` 覆盖。
- `mcp_kit::Manager` 支持自定义 untrusted 下的 `streamable_http` 出站策略：`with_untrusted_streamable_http_policy(UntrustedStreamableHttpPolicy)`。
- `mcpctl` 默认不信任本地配置：本地 stdio/unix 或需要读取 env secrets 的远程 server 需要 `--trust`。
- `mcp-jsonrpc` 增加 DoS 防护：限制单条消息大小并使用有界队列缓存 server→client 的 requests/notifications。
- `mcp-jsonrpc` 的 `streamable_http` 增加超时能力：默认 connect timeout=10s；可选 per-request timeout（`mcp-kit` 会用 `Manager` 的 per-request timeout 进行设置）。
- `mcp-jsonrpc` 的 `streamable_http` 默认不跟随 HTTP redirects（减少 SSRF 风险），可通过 `StreamableHttpOptions.follow_redirects` 显式开启。
- `mcp-jsonrpc` 的 stdout 旋转日志支持保留上限：`StdoutLog.max_parts`（`mcp-kit` 配置字段 `servers.<name>.stdout_log.max_parts`）。
- Docs: expand GitBook-style documentation under `docs/` and add `CONTRIBUTING.md`.
