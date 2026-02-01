# 传输层（stdio / unix / streamable_http）

`mcp-kit` 支持三种 transport，分别覆盖“本地 spawn”“本地 socket”“远程 HTTP”三类场景。

## transport=stdio（spawn 子进程）

适用：你要以 child process 的方式启动 MCP server（`--stdio`）。

配置字段（仅 stdio 支持）：

- `argv`（必填）：`["server-bin", "--stdio"]`
- `env`（可选）：注入到 child process 的环境变量
- `stdout_log`（可选）：将 server stdout 旋转落盘（便于排查协议/输出）

行为要点：

- `cwd`：child 的工作目录是 `--root`（CLI）或你传入 `Manager::connect(..., cwd)` 的目录
- `stderr`：默认继承到父进程（便于直接看到报错）
- `kill_on_drop = true`：连接被 drop 时，child 会被结束

安全：

- `TrustMode::Untrusted` 下会拒绝 spawn（见 [`安全模型`](security.md)）

## transport=unix（连接已存在的 unix socket）

适用：server 已经以守护进程或其他方式运行，并暴露 unix domain socket。

配置字段（仅 unix 支持）：

- `unix_path`（必填）：socket 路径（相对路径会按 `--root` 解析）

约束：

- 不支持 `argv/env/stdout_log`（因为不 spawn）

安全：

- `TrustMode::Untrusted` 下会拒绝连接（见 [`安全模型`](security.md)）

## transport=streamable_http（远程 HTTP SSE + POST）

适用：远程 MCP server。通常最推荐从这里开始。

配置字段（仅 streamable_http 支持）：

- `url`（必填）：例如 `https://example.com/mcp`
- `http_headers`（可选）：静态 header（不涉及 secrets 时可在 Untrusted 下使用）
- `bearer_token_env_var`（可选）：从 env 读取 token 并注入 `Authorization: Bearer ...`（Untrusted 下拒绝）
- `env_http_headers`（可选）：从 env 读取 header 值（Untrusted 下拒绝）

行为要点：

- 会自动添加 header：`MCP-Protocol-Version: <protocol_version>`
- 默认不跟随 redirects（减少 SSRF 风险；可在 `pm-jsonrpc` 里 opt-in）
- `pm-mcp-kit` 会把自己的 per-request timeout 设置到 `pm-jsonrpc` 的 HTTP request timeout

安全（Untrusted 默认策略）：

- 要求 `https://`
- 拒绝 localhost / *.localhost / *.local
- 拒绝非公网 IP 字面量
- 拒绝敏感 header（Authorization/Cookie/Proxy-Authorization）

详见 [`安全模型`](security.md)。

## 自定义 transport

如果你已经有一条读写管道，或者需要接入自建 transport（例如在测试里用 `tokio::io::duplex`）：

- `Manager::connect_io(server, read, write)`
- `Manager::connect_jsonrpc(server, pm_jsonrpc::Client)`

它们会复用同样的 initialize、超时、以及 server→client handler 逻辑。
