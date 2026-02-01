# FAQ

## Q：为什么默认连不上本地 `stdio/unix`？

因为 `mcp.json` 往往来自当前仓库/目录。对不可信仓库而言：

- `stdio` 等价于“按配置执行本地程序”
- `unix` 等价于“按配置连接本地 socket”

`pm-mcp-kit` 默认 `TrustMode::Untrusted`，会拒绝这两类危险动作。需要显式信任：

- CLI：`mcpctl --trust ...`
- 代码：`Manager::with_trust_mode(TrustMode::Trusted)`

详见 [`安全模型`](security.md)。

## Q：Untrusted 下可以用 token/auth 吗？

不可以。`bearer_token_env_var` 和 `env_http_headers` 会读取本地环境变量（secrets），在 Untrusted 下会被拒绝。

如果你确实要用认证 header：

- 用 `--trust`（或 `TrustMode::Trusted`）
- 或者在你自己的上层代码里自行注入 header（但同样建议只在可信环境启用）

## Q：`pm_mcp_kit::mcp` 的 typed wrapper 为什么不全？

这是一个“常用子集”，目标是低依赖、低维护成本。完整 schema 建议上层按需：

- 继续使用 `serde_json::Value`
- 或在你自己的 crate 中实现 `McpRequest/McpNotification` 扩展 typed 方法

## Q：是否支持自动重连/守护进程？

v1 不做。上层可以通过 drop/重建 `Manager` 或 `Session` 实现重连策略。

## Q：如何把连接交给其他库持有？

使用 `Manager::get_or_connect_session` / `take_session` 取出 `Session`，然后在其它模块里调用 `Session::{request, notify, list_tools, call_tool, ...}`。

## Q：如何处理 server→client 的 `roots/list`？

两种方式：

- 在 `mcp.json` 里配置 `client.roots`（推荐）
- 或用 `Manager::with_roots(...)`

启用后 `pm-mcp-kit` 会自动声明 `capabilities.roots`，并内建响应 `roots/list`。
