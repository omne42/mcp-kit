# 故障排查

本章按“报错信息 → 原因 → 解决方式”的形式整理常见问题。

## 配置加载阶段

### unsupported mcp.json version X (expected 1)

原因：当前只支持 `version: 1`。

解决：把 `mcp.json` 顶层 `version` 改为 `1`。

### invalid mcp server name: `<name>`

原因：server 名称只允许 `[a-zA-Z0-9_-]`。

解决：重命名 `servers` 的 key，例如 `my-server_1`。

### deny_unknown_fields / 未知字段导致解析失败

原因：对 `mcp.json v1` schema，`mcp-kit` 采用 fail-closed：顶层和 `servers.<name>` 都启用了 `deny_unknown_fields`。

说明：如果你使用的是 Cursor/Claude Code 常见的 `.mcp.json` / `mcpServers` 兼容格式，未知字段通常会被忽略；但字段类型不匹配、缺少必要字段仍会报错。

解决：删除拼写错误/未支持的字段；或升级代码以支持新字段。

### mcp config too large

原因：出于 DoS 防护，`mcp-kit` 会对配置文件读取做大小上限（当前为 4MiB），超过会拒绝加载。

解决：缩小配置文件（移除大块无关内容）；如果使用 `mcpServers: "path"` 等间接引用，确保被引用的目标文件也在大小上限内。

### mcp config must be a regular file

原因：出于安全考虑，配置文件（例如 `mcp.json` / `.mcp.json`）必须是普通文件；如果它是 symlink/目录/特殊文件，会被拒绝加载。

解决：把配置改为普通文件（不要用 symlink 指向其它位置）；确保路径指向真实文件且可读。

## 连接阶段（TrustMode）

### refusing to spawn mcp server in untrusted mode

原因：默认 `TrustMode::Untrusted` 禁止 `transport=stdio`。

解决：

- CLI：加 `--trust --yes-trust`
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

### refusing to connect localhost/local/single-label domain in untrusted mode

原因：默认拒绝 `localhost / *.localhost / *.local / *.localdomain`，以及**单标签 host**（不含 `.` 的 host）。

解决：

- CLI：加 `--allow-localhost`
- 代码：`UntrustedStreamableHttpPolicy { allow_localhost: true, .. }`

### refusing to connect non-global ip in untrusted mode

原因：默认拒绝 loopback/link-local/private 等非公网 IP 字面量。

解决：

- CLI：加 `--allow-private-ip`
- 代码：`UntrustedStreamableHttpPolicy { allow_private_ips: true, .. }`

### refusing to connect hostname that resolves to non-global ip in untrusted mode

原因：默认启用了 `dns_check`（或显式传了 CLI `--dns-check`），并且该 hostname 解析到了非公网 IP。

解决（任选其一）：

- 关闭 `dns_check`（或不传 `--dns-check`）
- CLI：加 `--allow-private-ip`（允许私网/loopback）
- 或使用 `--trust --yes-trust`（Trusted mode）

### refusing to connect hostname with failed/timed out dns lookup in untrusted mode

原因：默认启用了 `dns_check`（或显式传了 CLI `--dns-check`），但 DNS 解析失败或超时；默认策略是 fail-closed（直接拒绝连接）。

解决（任选其一）：

- 关闭 `dns_check`（或不传 `--dns-check`）
- CLI：调大 DNS timeout（`--dns-timeout-ms 5000`）
- CLI：如确实需要，可用 `--dns-fail-open` 忽略 DNS 失败/超时（风险更高）
- 修复本机 DNS（例如 VPN / 企业网 split-horizon / 网络策略导致的解析失败）
- 或使用 `--trust --yes-trust`（Trusted mode）

### refusing to send sensitive http header in untrusted mode

原因：默认拒绝 `Authorization` / `Proxy-Authorization` / `Cookie`。

解决：改为 `--trust --yes-trust`（或 Trusted mode）。

### refusing to read bearer token env var / refusing to read http header env vars

原因：读取 env secrets 只允许在 Trusted 下进行。

解决：改为 `--trust --yes-trust`（或 Trusted mode）。

## 超时与协议问题

### mcp request timed out

原因：网络问题、server 卡住、或 timeout 太短。

解决：

- CLI：调大 `--timeout-ms`
- 代码：`Manager::with_timeout(...)` 或 `Session::with_timeout(...)`

### client overloaded（-32000）

原因：`mcp-jsonrpc` 的 server→client requests 队列满，触发背压保护。

解决：

- 确保你在消费 `requests` channel（`mcp-kit` 默认会接管并消费）
- 或使用自建 `mcp_jsonrpc::Client`，调大 `SpawnOptions.limits.requests_capacity`，并在 `TrustMode::Trusted` 下用 `Manager::connect_jsonrpc(...)` 接入（或在测试场景用 `connect_jsonrpc_unchecked`）
