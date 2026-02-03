# mcpctl

`mcpctl` 是一个基于 `mcp.json` 的 MCP client/runner（config-driven; stdio/unix/streamable_http）。

它的定位是：

- 快速验证配置是否正确（`list-servers`）
- 探测 server 暴露的能力（tools/resources/prompts）
- 发送 raw request/notification 进行调试

## 运行方式

当前仓库内（推荐）：

```bash
cd mcp-kit
cargo run -p mcp-kit --features cli --bin mcpctl -- --help
```

> 注意：`mcpctl` 通过 feature `cli` 启用，避免 library 依赖方被迫引入 `clap`。

## 全局参数（flags）

- `--root <path>`：workspace root；用于相对路径解析，并作为 stdio server 的工作目录
- `--config <path>`：覆盖配置文件路径（绝对或相对 `--root`）
- `--json`：输出紧凑 JSON（默认 pretty JSON）
- `--timeout-ms <ms>`：per-request 超时（默认 30000）

安全相关：

- `--trust`：完全信任 `mcp.json`（允许 stdio/unix、允许读取 env secrets、允许发送认证 header）
- `--allow-stdout-log-outside-root`：允许 `stdout_log.path` 写到 `--root` 之外（默认拒绝；仅建议在可信配置下使用）
- `--show-argv`：`list-servers` 时输出 stdio `argv` 明文（默认不输出；避免把 token/key 打进终端/CI）
- `--allow-http`：Untrusted 下允许连接 `http://`（默认只允许 https）
- `--allow-localhost`：Untrusted 下允许连接 `localhost/*.localhost/*.local/*.localdomain`，以及**单标签 host**（不含 `.` 的 host，如 `https://example/...`；常见于本地/企业网搜索域解析）
- `--allow-private-ip`：Untrusted 下允许连接非公网 IP 字面量
- `--dns-check`：Untrusted 下对 hostnames 做 DNS 校验（解析到非公网 IP 会拒绝；除非同时允许 `--allow-private-ip`；DNS 失败/超时会拒绝）
- `--allow-host <host>`：Untrusted 下设置 host allowlist（可重复）

> `--allow-*` / `--dns-check` 只影响 `transport=streamable_http`，不会放开 stdio/unix（它们需要 `--trust`）。
>
> 注意：`--allow-host` allowlist **不会**覆盖上述 `localhost/localdomain/单标签 host` 的拦截；如需允许这些 host，请显式 `--allow-localhost` 或直接 `--trust`。

## 子命令（subcommands）

### list-servers

列出解析后的配置（包含 `client` 与 servers 的关键字段），用于确认最终生效值：

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- list-servers
```

说明：

- 为了避免意外打印 secrets，`list-servers` 默认不输出 stdio `argv` 明文；如需查看，显式加 `--show-argv`。
- 同样地，`list-servers` 对 `env/http_headers/env_http_headers` 只输出 key 列表（`env_keys/http_header_keys/env_http_header_keys`），不输出具体值。

### list-tools / list-resources / list-prompts

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- list-tools remote
cargo run -p mcp-kit --features cli --bin mcpctl -- list-resources remote
cargo run -p mcp-kit --features cli --bin mcpctl -- list-prompts remote
```

### call

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- call remote my.tool --arguments-json '{"k":"v"}'
```

### request（raw JSON-RPC request）

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- request remote tools/list
cargo run -p mcp-kit --features cli --bin mcpctl -- request remote resources/read --params-json '{"uri":"file:///path/to/file"}'
```

### notify（raw JSON-RPC notification）

```bash
cargo run -p mcp-kit --features cli --bin mcpctl -- notify remote notifications/initialized
```

## 常见用法组合

- 远程 server（https + 非 localhost/私网）：默认可用
- 本地 stdio/unix 或需要读取 env secrets：加 `--trust`
- 不完全信任但需要放开部分出站：使用 `--allow-host/--allow-http/...`

安全细节见 [`安全模型`](security.md)。
