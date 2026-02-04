# 核心概念与术语

本章是“词典 + 心智模型”：读完后你能快速理解 `mcp-kit` 在做什么、各组件怎么拼起来。

## MCP（Model Context Protocol）

MCP 是一种基于 **JSON-RPC 2.0** 的协议约定，用于让 “MCP client” 与 “MCP server” 交互。

常见交互包括：

- `initialize`：握手，交换 protocol/version/capabilities 等信息
- `tools/*`：列出并调用工具（tool）
- `resources/*`：列出并读取资源（resource）
- `prompts/*`：列出并获取 prompt 模板
- `logging/setLevel`：控制 server 侧日志等级
- `completion/complete`：补全相关能力（视 server 支持情况而定）

> `mcp-kit` 提供了常用 method 的便捷 API，但不试图覆盖完整 MCP schema。

## JSON-RPC 2.0

JSON-RPC 2.0 是一种轻量的 RPC 协议：

- request：包含 `id`，需要对端回复 response
- notification：不包含 `id`，对端无需回复
- response：对应某个 `id`，包含 `result` 或 `error`

MCP 约定的 method 名称（例如 `tools/list`）就是 JSON-RPC 的 `method` 字段。

## tool / resource / prompt

这三个是 MCP server 暴露给 client 的“能力面”：

- **tool**：可被调用的动作（例如搜索、读写、计算等）。调用入口通常是 `tools/call`。
- **resource**：可读取的内容（例如文件、网页、数据集）。读取入口通常是 `resources/read`。
- **prompt**：可参数化的 prompt 模板。读取入口通常是 `prompts/get`。

不同 server 对具体字段/能力的支持程度可能不同，因此 `mcp-kit` 的 typed wrapper 以常用字段为主；缺失部分可以继续用 `serde_json::Value` 处理。

## roots（根目录/根 URI）

MCP 的 roots 能力用于让 client 告诉 server：“我允许你把哪些目录/URI 当作工作根”。

在 `mcp-kit` 中：

- 你可以在 `mcp.json` 的 `client.roots` 配置 roots
- 或通过代码 `Manager::with_roots(...)` 注入

启用后会发生两件事：

1. initialize 的 `capabilities.roots` 会被自动声明
2. `mcp-kit` 会内建响应 server→client 的 `roots/list` request

## transport（传输方式）

`mcp-kit` 支持三种 transport（见 [`传输层`](transports.md)）：

- `stdio`：spawn 子进程，通过 stdin/stdout 交换 JSON-RPC 行
- `unix`：连接已存在的 unix domain socket
- `streamable_http`：远程 HTTP（SSE + POST），常用于远程 MCP server

## Config / Manager / Session（mcp-kit 三件套）

把它们理解成：**配置 → 多连接管理器 → 单连接会话**。

- `Config`：负责加载并校验 `mcp.json`（v1），得到一组 server 配置
- `Manager`：持有多个 server 的连接缓存；按需连接并执行 MCP initialize；提供便捷方法
- `Session`：一个“已 initialize 的单连接”，可交给其他模块/库独立持有与使用

常见使用路径：

1. `Config::load` 读取配置
2. `Manager::from_config` 创建 manager
3. `Manager::request/list_tools/call_tool/...` 发请求（内部会按需 connect + initialize）
4. （可选）`Manager::get_or_connect_session` 取出某个 server 的 `Session`，交给别的组件用

## TrustMode（信任模型）

`TrustMode` 是 `mcp-kit` 的关键安全开关（见 [`安全模型`](security.md)）：

- 默认 `Untrusted`：拒绝 `stdio/unix`（防止不可信仓库诱导本地执行/本地 socket 访问），并对 `streamable_http` 做保守出站校验
- `Trusted`：完全信任本地配置，允许本地 transport 与读取 env secrets 等

CLI 中：

- 默认等价于 `Untrusted`
- `mcpctl --trust --yes-trust` 等价于 `Trusted`

## UntrustedStreamableHttpPolicy（不完全信任下的出站策略）

当你不想完全 `--trust`，但又需要“更严格/更宽松”的远程连接策略时，可配置：

- 只允许特定 host（allowlist）
- 是否允许 `http://`
- 是否允许 localhost/私网 IP 字面量

这只影响 `transport=streamable_http`。
