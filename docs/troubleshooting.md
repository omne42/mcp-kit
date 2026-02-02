# 故障排查

本章按“报错信息 → 原因 → 解决方式”的形式整理常见问题。

## 配置加载阶段

### unsupported mcp.json version X (expected 1)

原因：当前只支持 `version: 1`。

解决：把 `mcp.json` 顶层 `version` 改为 `1`。

### invalid mcp server name: <name>

原因：server 名称只允许 `[a-zA-Z0-9_-]`。

解决：重命名 `servers` 的 key，例如 `my-server_1`。

### deny_unknown_fields / 未知字段导致解析失败

原因：schema 是 fail-closed，顶层和 `servers.<name>` 都启用了 `deny_unknown_fields`。

解决：删除拼写错误/未支持的字段；或升级代码以支持新字段。

## 连接阶段（TrustMode）

### refusing to spawn mcp server in untrusted mode

原因：默认 `TrustMode::Untrusted` 禁止 `transport=stdio`。

解决：

- CLI：加 `--trust`
- 代码：`Manager::with_trust_mode(TrustMode::Trusted)`

### refusing to connect unix mcp server in untrusted mode

原因：默认 `TrustMode::Untrusted` 禁止 `transport=unix`。

解决：同上。

## 远程 streamable_http（出站校验）

### refusing to connect non-https streamable http url in untrusted mode

原因：默认要求 `https://`。

解决（任选其一）：

- 改用 `https://`
- CLI：加 `--allow-http`
- 代码：`UntrustedStreamableHttpPolicy { require_https: false, .. }`

### refusing to connect localhost/local domain in untrusted mode

原因：默认拒绝 `localhost / *.localhost / *.local`。

解决：

- CLI：加 `--allow-localhost`
- 代码：`UntrustedStreamableHttpPolicy { allow_localhost: true, .. }`

### refusing to connect non-global ip in untrusted mode

原因：默认拒绝 loopback/link-local/private 等非公网 IP 字面量。

解决：

- CLI：加 `--allow-private-ip`
- 代码：`UntrustedStreamableHttpPolicy { allow_private_ips: true, .. }`

### refusing to connect hostname that resolves to non-global ip in untrusted mode

原因：启用了 `dns_check`（或 CLI `--dns-check`），并且该 hostname 解析到了非公网 IP。

解决（任选其一）：

- 关闭 `dns_check`（或不传 `--dns-check`）
- CLI：加 `--allow-private-ip`（允许私网/loopback）
- 或使用 `--trust`（Trusted mode）

### refusing to send sensitive http header in untrusted mode

原因：默认拒绝 `Authorization` / `Proxy-Authorization` / `Cookie`。

解决：改为 `--trust`（或 Trusted mode）。

### refusing to read bearer token env var / refusing to read http header env vars

原因：读取 env secrets 只允许在 Trusted 下进行。

解决：改为 `--trust`（或 Trusted mode）。

## 超时与协议问题

### mcp request timed out: <method>

原因：网络问题、server 卡住、或 timeout 太短。

解决：

- CLI：调大 `--timeout-ms`
- 代码：`Manager::with_timeout(...)` 或 `Session::with_timeout(...)`

### client overloaded（-32000）

原因：`mcp-jsonrpc` 的 server→client requests 队列满，触发背压保护。

解决：

- 确保你在消费 `requests` channel（`mcp-kit` 默认会接管并消费）
- 或使用自建 `mcp_jsonrpc::Client`，调大 `SpawnOptions.limits.requests_capacity` 再 `Manager::connect_jsonrpc(...)`
