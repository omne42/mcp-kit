# 安全模型（TrustMode）

本章解释 `mcp-kit` 为什么默认会“拒绝某些连接”，以及如何在**可控范围内**放开限制。

## 威胁模型：为什么需要 TrustMode？

`mcp.json` 往往来自“当前工作目录/仓库”。当你在一个不可信仓库里运行 MCP client 时，配置本身可能诱导客户端做出危险动作，例如：

- `transport=stdio`：spawn 任意本地程序（等价于本地代码执行入口）。
- `transport=unix`：连接任意 unix socket（可能访问本机敏感服务）。
- `transport=streamable_http`：连接恶意 URL（可能 SSRF 到内网/本机），或携带敏感 header/token 外带 secrets。

因此 `mcp-kit` 选择：**默认不信任本地配置（fail-closed）**。

## TrustMode：Trusted vs Untrusted

`mcp_kit::TrustMode`：

- `Untrusted`（默认）：拒绝“本地危险动作”，并对远程出站做保守校验。
- `Trusted`：完全信任配置，允许 `stdio/unix`，并允许发送敏感 header、读取 env secrets 等。

CLI 对应：

- `mcpctl` 默认等价于 `Untrusted`
- `mcpctl --trust --yes-trust` 等价于 `Trusted`

## Untrusted 下的具体限制（行为精确对应代码实现）

### 1）禁止本地 transport

- `transport=stdio`：直接拒绝（报错提示需要 `TrustMode::Trusted`）
- `transport=unix`：直接拒绝

### 2）远程 `streamable_http` 出站校验

默认 `UntrustedStreamableHttpPolicy`：

- `require_https = true`：只允许 `https://`
- `allow_localhost = false`：拒绝 `localhost` / `*.localhost` / `*.local` / `*.localdomain`，以及**单标签 host**（不含 `.` 的 host，如 `https://example/...`；常见于本地/企业网搜索域解析）
- `allow_private_ips = false`：拒绝 loopback/link-local/private 等非公网 IP 字面量
- `dns_check = false`：默认不做 DNS 解析检查（可选开启；见下文）
- `dns_timeout = 2s`：DNS lookup 超时（仅在 `dns_check=true` 时生效）
- `dns_fail_open = false`：DNS lookup 失败/超时时默认拒绝连接（fail-closed；可选 fail-open）
- `allowed_hosts = []`：默认不做 host allowlist；一旦配置 allowlist，则只允许 allowlist 命中的 host/子域名

补充说明：

- allowlist（`allowed_hosts` / `--allow-host`）不会覆盖 `allow_localhost=false` 下的 `localhost/localdomain/单标签 host` 拒绝逻辑；如需允许这些 host，请显式开启 `allow_localhost` / `--allow-localhost` 或直接使用 `Trusted`。

另外，Untrusted 下还会拒绝：

- URL 中带 `user:pass@host` 形式的“URL credentials”
- 发送敏感 header：`Authorization` / `Proxy-Authorization` / `Cookie`

### 3）禁止读取 env secrets（用于认证 header）

在 `streamable_http` 配置中：

- `bearer_token_env_var`
- `env_http_headers`

这两类会从本地环境变量读取 secrets。在 `Untrusted` 下会直接拒绝读取。

## 如何放开：三种层级

### A. 完全信任（最简单）

- CLI：`mcpctl --trust --yes-trust ...`
- 代码：`Manager::with_trust_mode(TrustMode::Trusted)`

适用：你明确知道自己在可信仓库、可信二进制、可信网络环境中。

### B. 不完全信任，但允许有限出站（推荐）

通过 `UntrustedStreamableHttpPolicy` 收紧/放开“远程连接”规则（只影响 `streamable_http`）：

- CLI：`--allow-http` / `--allow-localhost` / `--allow-private-ip` / `--allow-host <host>` / `--dns-check`
- 代码：`Manager::with_untrusted_streamable_http_policy(...)`

建议用法：

- 尽量用 `allowed_hosts` 做 allowlist（把出站面收敛到最小）
- 除非必要，不要开启 `allow_http` / `allow_private_ip` / `allow_localhost`

### C. 精细化：自定义 header / token 注入（Trusted 才允许）

当你需要认证（Bearer token / API key / Cookie 等）时，推荐做法是：

- 不要把 secrets 写进 `mcp.json`
- 用环境变量保存 secrets，再通过 `bearer_token_env_var` / `env_http_headers` 注入

但请注意：为了防止“不可信仓库借配置外带本机 secrets”，上述两项在 `Untrusted` 下会被拒绝读取，因此需要：

- CLI：`--trust --yes-trust`
- 或代码：`Manager::with_trust_mode(TrustMode::Trusted)`

## 重要注意点（限制与最佳实践）

### IP 校验只覆盖“IP 字面量”

Untrusted 下对 `127.0.0.1`、`10.0.0.0/8` 等 **IP 字面量** 会做拒绝/允许判断；但对域名（如 `example.com`）不会在此处做 DNS 解析与再校验。

因此如果你想降低 SSRF 风险，强烈建议：

- 使用 `allowed_hosts`（或 CLI `--allow-host`）做 host allowlist
- 避免在 Untrusted 下开启 `--allow-localhost/--allow-private-ip/--allow-http`

如果你希望降低“域名解析到私网”的 SSRF 风险，可以开启 `dns_check`（或 CLI `--dns-check`）。开启后：

- hostnames 会做一次 DNS 解析（带超时；默认 2s，CLI 可用 `--dns-timeout-ms` 调整）；若解析到非公网 IP，会被拒绝（除非同时允许 `allow_private_ips` 或使用 `Trusted`）
- DNS 解析失败/超时默认会直接拒绝连接（fail-closed）；如确实需要（例如企业网/VPN 的 DNS 不稳定），可以显式开启 `dns_fail_open` / `--dns-fail-open` 让 DNS 失败时不拦截（风险更高）
- 仍然不能完全防住 DNS rebinding；更强的威胁模型需要更底层的网络出站控制

建议：

- 当你需要在 Untrusted 下允许某些 hostname（例如使用 `allowed_hosts`/`--allow-host` 放开出站）且希望额外降低“域名解析到私网”的 SSRF 风险时，可以考虑开启 `dns_check`。
- `dns_check` 只在 `allow_private_ips=false` 时有效；如果你同时开启了 `allow_private_ips`/`--allow-private-ip`，则解析到私网不再会被拒绝。
- `dns_check` 会增加一次 DNS 解析（带超时），并可能在 VPN/企业网 split-horizon DNS 环境中产生误判；同时也无法彻底防住 rebinding。

### Redirects 默认禁用

`mcp-jsonrpc` 的 streamable_http 默认不跟随 HTTP redirects（`follow_redirects=false`），这是额外的一层 SSRF 风险降低。即使在 `Trusted` 下，该默认仍然生效（除非你在自己的 `mcp_jsonrpc::Client` 中显式开启）。

### 自定义 transport（`connect_jsonrpc` / `connect_io`）

当你用 `Manager::connect_jsonrpc(...)` / `connect_io(...)` 接入自建 transport 时，`Manager` 无法再对该 transport 做 `Untrusted` 下的 URL/headers 等安全校验。

因此这两者默认要求 `TrustMode::Trusted`；如果你确实需要在 Untrusted 下使用（例如测试），请显式使用 `connect_jsonrpc_unchecked` / `connect_io_unchecked`，并把它视为一次“我知道我在绕过安全护栏”的选择。

### 仍然把 `mcp.json` 当作不可信输入

即使你愿意在某些场景使用 `--trust`，也建议把它当作一次“显式的安全决策”：

- CI/自动化脚本里谨慎使用 `--trust`
- 对外部贡献的仓库默认保持 Untrusted
- 对远程连接尽量收敛出站面（allowlist host），并对认证信息做最小化暴露
