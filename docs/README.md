# mcp-kit 文档

`mcp-kit` 是一个 **Rust workspace**，提供可复用的 MCP client/runner 组件：

- `pm-jsonrpc`：最小 JSON-RPC 2.0 client（stdio / unix / streamable_http），支持 notification 与 server→client request，并内置 DoS 防护（有界队列 + 单消息大小限制）。
- `pm-mcp-kit`：`mcp.json`（v1）解析 + MCP 连接/初始化 + 会话管理（`Config / Manager / Session`），并提供常用 MCP 方法的便捷封装。
- `mcpctl`：基于 `mcp.json` 的 CLI（用于快速验证配置、探测 server 的 tools/resources/prompts 等）。

## 设计原则（读这个能少踩坑）

- **Remote-first**：原生支持远程 `transport=streamable_http`（HTTP SSE + POST）。
- **Safe-by-default**：默认 `TrustMode::Untrusted`，拒绝本地 `stdio/unix`（避免不可信仓库触发本地执行/本地 socket 访问），并对远程出站做保守校验。
- **低依赖、低仪式感**：数据层以 `serde_json::Value` 为主，typed wrapper 只覆盖常用 MCP 方法子集。
- **可组合**：既能用 `Manager` 一把梭，也能把单 server 的 `Session` 交给其他库持有；还可通过 `connect_io/connect_jsonrpc` 接入自定义 transport。

## 从哪里开始

- 新手：先看 [`快速开始`](quickstart.md)（5 分钟跑通 `mcpctl` + 代码调用）。
- 配置：看 [`配置`](config.md)（发现顺序、schema、每种 transport 的字段与约束）。
- CLI：看 [`CLI：mcpctl`](cli.md)（所有 flag/subcommand 的行为与示例）。
- 作为库：看 [`作为库使用`](library.md)（`Config/Manager/Session` 最佳实践）。
- 安全：看 [`安全模型`](security.md)（为什么默认不信任、哪些会被拒绝、如何按需放开）。
- 传输：看 [`传输层`](transports.md)（stdio/unix/streamable_http 的差异与限制）。
- 底层 JSON-RPC：看 [`pm-jsonrpc`](jsonrpc.md)（队列/限制/handler 的用法）。
- API 索引：看 [`API 参考`](api.md)。

## 目录导航（GitBook）

如果你用 GitBook/HonKit 一类工具渲染这套文档，入口是：

- `docs/README.md`（本页）
- `docs/SUMMARY.md`（目录）
